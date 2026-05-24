"""
Main Application Entry Point
Orchestrates all agents and runs the system
"""
import asyncio
import uvicorn
import threading
from datetime import datetime

from models import DataSource
from llm_wrapper import LLMWrapper
from agents.ingestion import IngestionAgent
from agents.enrichment import EnrichmentAgent
from agents.pattern_discovery import PatternDiscoveryAgent
from agents.mitigation import MitigationAgent
from agents.validation import ValidationAgent
from agents.classifier import ClassifierAgent
from agents.evaluator import EvaluatorAgent
from agents.chatbot import CTIChatbot
from streaming.feeds import FeedStreamer
from rag.vector_store import CTIVectorStore
from rag.mitre_loader import MitreAttackLoader
from rag.retriever import CTIRetriever
import app
import config


class CTISystem:
    """Main CTI Agentic System"""

    def __init__(self):
        self.running = False

        print("Initializing LLM wrapper...")
        self.llm = LLMWrapper()

        print("Initializing RAG knowledge base...")
        try:
            self.vector_store = CTIVectorStore()
            mitre_loader = MitreAttackLoader(self.vector_store)
            mitre_loader.load()
            self.retriever = CTIRetriever(self.vector_store)
            print("✓ RAG ready")
        except Exception as e:
            print(f"⚠ RAG initialization failed ({e}), continuing without RAG")
            self.retriever = None

        print("Initializing agents...")
        self.ingestion_agent = IngestionAgent()
        self.enrichment_agent = EnrichmentAgent(self.llm, retriever=self.retriever)
        self.pattern_agent = PatternDiscoveryAgent()
        self.mitigation_agent = MitigationAgent(self.llm)
        self.validation_agent = ValidationAgent()
        self.classifier_agent = ClassifierAgent(self.llm)
        self.evaluator_agent = EvaluatorAgent(self.llm)
        self.chatbot_agent = CTIChatbot(self.llm, app.state)
        self.feed_streamer = FeedStreamer(app.state)
        print("✓ System initialized")

    def check_llm(self) -> bool:
        print("\nChecking LLM availability...")
        if not self.llm.is_available():
            print("⚠ LLM not available. Attempting to pull model...")
            if not self.llm.pull_model():
                print("\n✗ LLM setup failed! Run: python setup_ollama.py")
                return False
        print("✓ LLM is ready")
        return True

    def collect_logs(self):
        all_logs = []
        all_logs.extend(self.ingestion_agent.log_entries)
        all_logs.extend(self.enrichment_agent.log_entries)
        all_logs.extend(self.pattern_agent.log_entries)
        all_logs.extend(self.mitigation_agent.log_entries)
        all_logs.extend(self.validation_agent.log_entries)
        all_logs.extend(self.classifier_agent.log_entries)
        all_logs.extend(self.evaluator_agent.log_entries)
        all_logs.sort(key=lambda x: x.timestamp)
        return all_logs

    def update_app_state(self):
        sources = [DataSource(
            name="Local Files",
            source_type="file",
            location=str(config.INPUT_DIR),
            status="active",
            last_polled=datetime.now(),
            events_count=len(app.state['events'])
        )]
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
        app.state['classifications'] = self.classifier_agent.get_all_classifications()
        app.state['benchmark_results'] = self.evaluator_agent.get_all_results()

    async def process_cycle(self):
        try:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"\n[{ts}] Starting processing cycle...")
            app.state['pipeline_status'] = 'running'

            print("  [1/5] Ingesting data...")
            app.state['current_pipeline_step'] = 1
            new_events = await self.ingestion_agent.ingest_all()

            pending = list(app.state.get('pending_events', []))
            if pending:
                print(f"  → {len(pending)} live-submitted events in queue")
                new_events = pending + new_events
                app.state['pending_events'].clear()

            if not new_events:
                print("  → No new events")
                return

            print(f"  → Ingesting {len(new_events)} new events")

            file_events = [e for e in new_events if e not in pending]
            app.state['events'].extend(file_events)
            if len(app.state['events']) > config.MAX_EVENTS_STORED:
                app.state['events'] = (
                    app.state['events'][-config.MAX_EVENTS_STORED:]
                )
            self.update_app_state()

            print("  [2/5] Enriching events with LLM...")
            app.state['current_pipeline_step'] = 2
            enriched = []
            batch = new_events[:config.MAX_EVENTS_PER_CYCLE]
            for i, event in enumerate(batch):
                print(
                    f"    Enriching event {i+1}/{len(batch)}: "
                    f"{event.event_id[:8]}..."
                )
                result = await self.enrichment_agent.enrich_event(event)
                if result:
                    enriched.append(result)
                    app.state['enriched_events'].append(result)
                self.update_app_state()
            print(f"  → Enriched {len(enriched)} events")

            if len(app.state['enriched_events']) > config.MAX_EVENTS_STORED:
                app.state['enriched_events'] = (
                    app.state['enriched_events'][-config.MAX_EVENTS_STORED:]
                )

            if enriched:
                print(f"  [2b] Classifying {len(enriched)} enriched events...")
                classifications = await self.classifier_agent.classify_batch(
                    enriched
                )
                print(f"  → Classified {len(classifications)} events")
                self.update_app_state()

            print("  [3/5] Discovering patterns...")
            app.state['current_pipeline_step'] = 3
            new_patterns = await self.pattern_agent.discover_patterns(enriched)
            print(f"  → Discovered {len(new_patterns)} new patterns")
            self.update_app_state()

            print("  [4/5] Generating mitigations...")
            app.state['current_pipeline_step'] = 4
            new_mitigations = await self.mitigation_agent.generate_mitigations(
                new_patterns, enriched
            )
            print(f"  → Generated {len(new_mitigations)} mitigations")
            self.update_app_state()

            print("  [5/5] Validating mitigations...")
            app.state['current_pipeline_step'] = 5
            validated = await self.validation_agent.validate_batch(
                new_mitigations
            )
            passed = sum(1 for m in validated if m.validated)
            print(f"  → Validated {passed}/{len(validated)} mitigations")

            self.update_app_state()
            print("  ✓ Cycle complete\n")
            app.state['current_pipeline_step'] = 0
            app.state['pipeline_status'] = 'idle'

        except Exception as e:
            import traceback
            print(f"  ✗ Error in processing cycle: {e}")
            traceback.print_exc()
            self.update_app_state()

    async def run_processing_loop(self):
        self.running = True
        sep = '=' * 70
        print(f"\n{sep}")
        print("STARTING CTI PROCESSING LOOP")
        print(sep)
        print(f"Polling interval: {config.POLLING_INTERVAL} seconds")
        print(f"Input directory:  {config.INPUT_DIR}")
        print(f"{sep}\n")

        app.state['feed_streamer'] = self.feed_streamer
        if config.ENABLE_FEEDS:
            print("📡 Starting real-time feed streaming...")
            self.feed_streamer.start()
            print("  ✓ Feed streamer active (Mastodon Local, #threatintel, #ioc)\n")
        else:
            print("  ⏸  Feed streaming DISABLED (ENABLE_FEEDS=False in config.py)\n")

        wake = asyncio.Event()
        app.state['wake_event'] = wake

        while self.running:
            if app.state.get('pipeline_paused', False):
                await asyncio.sleep(1)
                continue
            await self.process_cycle()

            if config.ENABLE_FEEDS and app.state.pop('feeds_paused_for_user', False):
                self.feed_streamer.resume()

            wake.clear()
            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=config.POLLING_INTERVAL
                )
                print("  [loop] Woken early by user submission")
            except asyncio.TimeoutError:
                pass

    def stop(self):
        self.running = False
        self.feed_streamer.stop()
        print("\n✓ System stopped")


def run_web_server():
    uvicorn.run(
        app.app,
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        log_level="info"
    )


# Stored so app.py state['system'] is the canonical reference (no import needed)
_system_instance = None


def main():
    global _system_instance
    sep = '=' * 70
    print(f"\n{sep}")
    print("CTI AGENTIC SYSTEM")
    print("Real-Time Threat Intelligence with Local LLM")
    print(f"{sep}\n")

    system = CTISystem()
    _system_instance = system
    app.state['system'] = system

    if not system.check_llm():
        return

    print(f"\n{sep}")
    print("SYSTEM READY")
    print(sep)
    print(f"\n📊 Dashboard: http://localhost:{config.WEB_PORT}")
    print(f"📁 Input directory: {config.INPUT_DIR}")
    print(f"\nDrop CTI files into the input directory to process them.")
    print(f"Auto-polls every {config.POLLING_INTERVAL} seconds.\n")

    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()

    import time
    time.sleep(2)
    print(f"✓ Web server started on http://localhost:{config.WEB_PORT}\n")

    try:
        asyncio.run(system.run_processing_loop())
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        system.stop()
        print("Goodbye!\n")


if __name__ == "__main__":
    main()
