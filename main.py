"""
Main Application Entry Point
Orchestrates all agents and runs the system
"""
import asyncio
import uvicorn
import threading
from datetime import datetime
from typing import List

from models import DataSource
from llm_wrapper import LLMWrapper
from agents.ingestion import IngestionAgent
from agents.enrichment import EnrichmentAgent
from agents.pattern_discovery import PatternDiscoveryAgent
from agents.mitigation import MitigationAgent
from agents.validation import ValidationAgent
from streaming.feeds import FeedStreamer
import app
import config


class CTISystem:
    """Main CTI Agentic System"""
    
    def __init__(self):
        self.running = False
        
        # Initialize LLM
        print("Initializing LLM wrapper...")
        self.llm = LLMWrapper()
        
        # Initialize agents
        print("Initializing agents...")
        self.ingestion_agent = IngestionAgent()
        self.enrichment_agent = EnrichmentAgent(self.llm)
        self.pattern_agent = PatternDiscoveryAgent()
        self.mitigation_agent = MitigationAgent(self.llm)
        self.validation_agent = ValidationAgent()
        
        # Initialize feed streamer
        self.feed_streamer = FeedStreamer(app.state)
        
        print("\u2713 System initialized")
    
    def check_llm(self) -> bool:
        """Check if LLM is available"""
        print("\nChecking LLM availability...")
        
        if not self.llm.is_available():
            print("⚠ LLM not available. Attempting to pull model...")
            if not self.llm.pull_model():
                print("\n✗ LLM setup failed!")
                print("\nPlease run: python setup_ollama.py")
                return False
        
        print("✓ LLM is ready")
        return True
    
    def collect_logs(self):
        """Collect logs from all agents"""
        all_logs = []
        all_logs.extend(self.ingestion_agent.log_entries)
        all_logs.extend(self.enrichment_agent.log_entries)
        all_logs.extend(self.pattern_agent.log_entries)
        all_logs.extend(self.mitigation_agent.log_entries)
        all_logs.extend(self.validation_agent.log_entries)
        
        # Sort by timestamp
        all_logs.sort(key=lambda x: x.timestamp)
        
        return all_logs
    
    def update_app_state(self):
        """Update FastAPI app state with current data"""
        # Update data sources
        sources = []
        sources.append(DataSource(
            name="Local Files",
            source_type="file",
            location=str(config.INPUT_DIR),
            status="active",
            last_polled=datetime.now(),
            events_count=len(app.state['events'])
        ))
        
        for url in config.EXTERNAL_FEEDS:
            sources.append(DataSource(
                name=f"Feed: {url[:50]}",
                source_type="url",
                location=url,
                status="active",
                last_polled=datetime.now(),
                events_count=0
            ))
        
        app.state['data_sources'] = sources
        app.state['agent_logs'] = self.collect_logs()
        app.state['patterns'] = self.pattern_agent.get_all_patterns()
        app.state['mitigations'] = self.mitigation_agent.get_all_mitigations()
    
    async def process_cycle(self):
        """Single processing cycle"""
        try:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting processing cycle...")
            app.state['pipeline_status'] = 'running'
            
            # Step 1: Ingest new events (from files)
            print("  [1/5] Ingesting data...")
            app.state['current_pipeline_step'] = 1
            new_events = await self.ingestion_agent.ingest_all()
            
            # Also drain real-time submitted events from the pending queue
            pending = list(app.state.get('pending_events', []))
            if pending:
                print(f"  → {len(pending)} live-submitted events in queue")
                new_events.extend(pending)
                app.state['pending_events'].clear()
            
            if not new_events:
                print("  → No new events")
                return
            
            print(f"  → Ingesting {len(new_events)} new events")
            
            # Add to state immediately so dashboard can show raw events
            # (pending events are already in state['events'] from the API, so only add file events)
            file_events = [e for e in new_events if e not in pending]
            app.state['events'].extend(file_events)
            if len(app.state['events']) > config.MAX_EVENTS_STORED:
                app.state['events'] = app.state['events'][-config.MAX_EVENTS_STORED:]
            self.update_app_state()
            
            # Step 2: Enrich events (one at a time, pushing state after each)
            print("  [2/5] Enriching events with LLM...")
            app.state['current_pipeline_step'] = 2
            enriched = []
            batch = new_events[:config.MAX_EVENTS_PER_CYCLE]
            for i, event in enumerate(batch):
                print(f"    Enriching event {i+1}/{len(batch)}: {event.event_id[:8]}...")
                result = await self.enrichment_agent.enrich_event(event)
                if result:
                    enriched.append(result)
                    app.state['enriched_events'].append(result)
                # Push state after each enrichment so dashboard updates live
                self.update_app_state()
            print(f"  → Enriched {len(enriched)} events")
            
            if len(app.state['enriched_events']) > config.MAX_EVENTS_STORED:
                app.state['enriched_events'] = app.state['enriched_events'][-config.MAX_EVENTS_STORED:]
            
            # Step 3: Discover patterns
            print("  [3/5] Discovering patterns...")
            app.state['current_pipeline_step'] = 3
            new_patterns = await self.pattern_agent.discover_patterns(enriched)
            print(f"  → Discovered {len(new_patterns)} new patterns")
            self.update_app_state()
            
            # Step 4: Generate mitigations
            print("  [4/5] Generating mitigations...")
            app.state['current_pipeline_step'] = 4
            new_mitigations = await self.mitigation_agent.generate_mitigations(
                new_patterns, 
                enriched
            )
            print(f"  → Generated {len(new_mitigations)} mitigations")
            self.update_app_state()
            
            # Step 5: Validate mitigations
            print("  [5/5] Validating mitigations...")
            app.state['current_pipeline_step'] = 5
            validated = await self.validation_agent.validate_batch(new_mitigations)
            passed = sum(1 for m in validated if m.validated)
            print(f"  → Validated {passed}/{len(validated)} mitigations")
            
            # Final state update
            self.update_app_state()
            
            print(f"  ✓ Cycle complete\n")
            app.state['current_pipeline_step'] = 0
            app.state['pipeline_status'] = 'idle'
            
        except Exception as e:
            import traceback
            print(f"  ✗ Error in processing cycle: {e}")
            traceback.print_exc()
            self.update_app_state()
    
    async def run_processing_loop(self):
        """Main processing loop"""
        self.running = True
        print(f"\n{'='*70}")
        print("STARTING CTI PROCESSING LOOP")
        print(f"{'='*70}")
        print(f"Polling interval: {config.POLLING_INTERVAL} seconds")
        print(f"Input directory: {config.INPUT_DIR}")
        print(f"{'='*70}\n")
        
        # Start real-time feed streaming
        print("\U0001f4e1 Starting real-time feed streaming...")
        self.feed_streamer.start()
        app.state['feed_streamer'] = self.feed_streamer
        print("  \u2713 Feed streamer active (URLhaus, ThreatFox, Feodo Tracker)\n")
        
        while self.running:
            await self.process_cycle()
            await asyncio.sleep(config.POLLING_INTERVAL)
    
    def stop(self):
        """Stop the system"""
        self.running = False
        self.feed_streamer.stop()
        print("\n\u2713 System stopped")


def run_web_server():
    """Run the web server"""
    uvicorn.run(
        app.app,
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        log_level="info"
    )


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("CTI AGENTIC SYSTEM")
    print("Real-Time Threat Intelligence with Local LLM")
    print("="*70 + "\n")
    
    # Initialize system
    system = CTISystem()
    
    # Check LLM
    if not system.check_llm():
        return
    
    print("\n" + "="*70)
    print("SYSTEM READY")
    print("="*70)
    print(f"\n📊 Dashboard: http://localhost:{config.WEB_PORT}")
    print(f"📁 Input directory: {config.INPUT_DIR}")
    print(f"\nDrop CTI files (CSV/JSON) into the input directory to process them.")
    print(f"The system will auto-poll every {config.POLLING_INTERVAL} seconds.\n")
    
    # Start web server in background thread
    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()
    
    # Give web server time to start
    import time
    time.sleep(2)
    
    print(f"✓ Web server started on http://localhost:{config.WEB_PORT}\n")
    
    # Run processing loop
    try:
        asyncio.run(system.run_processing_loop())
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        system.stop()
        print("Goodbye!\n")


if __name__ == "__main__":
    main()
