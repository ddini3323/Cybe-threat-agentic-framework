"""
Agent 5: Validation Agent
Validates mitigation recommendations for safety and correctness
"""
from typing import List
from models import MitigationAction, AgentLogEntry


class ValidationAgent:
    """Agent responsible for validating mitigations"""
    
    def __init__(self):
        self.name = "ValidationAgent"
        self.log_entries: List[AgentLogEntry] = []
    
    def _log(self, action: str, details: str, mitigation_id: str = None, status: str = "success"):
        """Create log entry"""
        entry = AgentLogEntry(
            agent_name=self.name,
            action=action,
            details=details,
            mitigation_id=mitigation_id,
            status=status
        )
        self.log_entries.append(entry)
        return entry
    
    def _check_dangerous_commands(self, rule: str) -> bool:
        """Check if rule contains dangerous commands"""
        if not rule:
            return False
        
        rule_lower = rule.lower()
        
        # Dangerous patterns
        dangerous = [
            'rm -rf /',
            'format c:',
            'del /f /s /q',
            'drop database',
            'truncate table',
            '0.0.0.0/0',  # Block all IPs
            'any any any any',  # Overly broad rule
        ]
        
        return any(danger in rule_lower for danger in dangerous)
    
    def _check_overly_broad(self, mitigation: MitigationAction) -> bool:
        """Check if mitigation is overly broad"""
        title_desc = (mitigation.title + ' ' + mitigation.description).lower()
        
        # Overly broad indicators
        broad_terms = [
            'block all',
            'disable all',
            'shutdown all',
            'delete all',
            'remove all'
        ]
        
        return any(term in title_desc for term in broad_terms)
    
    def _check_completeness(self, mitigation: MitigationAction) -> bool:
        """Check if mitigation has sufficient detail"""
        # Must have title, description, and at least 2 steps
        if not mitigation.title or not mitigation.description:
            return False
        
        if not mitigation.steps or len(mitigation.steps) < 2:
            return False
        
        # Steps should be substantial
        if any(len(step.strip()) < 10 for step in mitigation.steps):
            return False
        
        return True
    
    async def validate_mitigation(self, mitigation: MitigationAction) -> bool:
        """Validate a single mitigation"""
        issues = []
        
        # Check completeness
        if not self._check_completeness(mitigation):
            issues.append("Insufficient detail or missing steps")
        
        # Check for dangerous commands
        if mitigation.sample_rule and self._check_dangerous_commands(mitigation.sample_rule):
            issues.append("Contains potentially dangerous commands")
        
        # Check if overly broad
        if self._check_overly_broad(mitigation):
            issues.append("Mitigation may be overly broad")
        
        # Log results
        if issues:
            mitigation.validated = False
            self._log("validate_mitigation",
                     f"Mitigation {mitigation.mitigation_id} failed validation: {'; '.join(issues)}",
                     mitigation.mitigation_id, status="warning")
            return False
        else:
            mitigation.validated = True
            self._log("validate_mitigation",
                     f"Mitigation {mitigation.mitigation_id} passed validation",
                     mitigation.mitigation_id)
            return True
    
    async def validate_batch(self, mitigations: List[MitigationAction]) -> List[MitigationAction]:
        """Validate a batch of mitigations"""
        if not mitigations:
            return []
        
        self._log("validate_batch", f"Validating {len(mitigations)} mitigations")
        
        validated = []
        for mitigation in mitigations:
            await self.validate_mitigation(mitigation)
            validated.append(mitigation)
        
        passed = sum(1 for m in validated if m.validated)
        self._log("validate_batch", 
                 f"Validation complete: {passed}/{len(validated)} passed")
        
        return validated
