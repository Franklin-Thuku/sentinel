"""
AI Service for Sentinel.

Handles AI-powered analysis of security findings using multiple providers.
Supports OpenAI, Anthropic, Google Gemini, and mock providers.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Type
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models.finding import Finding
from app.db.models.ai_analysis import AIAnalysis
from app.db.models.scan import Scan
from app.db.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AIService:
    """
    Service for AI-powered security analysis.

    Supports multiple AI providers:
    - OpenAI (GPT-4, GPT-3.5)
    - Anthropic (Claude)
    - Google Gemini
    - Mock (for testing)
    """

    def __init__(self, db: Session):
        """
        Initialize the AI service.

        Args:
            db: Database session
        """
        self.db = db
        self.provider = settings.AI_PROVIDER
        self.api_key = settings.AI_API_KEY.get_secret_value() if settings.AI_API_KEY else None
        self.model = settings.AI_MODEL

        # Initialize the appropriate client
        self._client = None
        self._init_client()

    def _init_client(self) -> None:
        """Initialize the AI client based on provider configuration."""
        if not self.provider or self.provider == "mock":
            logger.info("AI provider set to 'mock' - using mock responses")
            return

        if not self.api_key:
            logger.warning("AI_API_KEY not set - falling back to mock mode")
            self.provider = "mock"
            return

        try:
            if self.provider == "openai":
                import openai
                self._client = openai.OpenAI(api_key=self.api_key)
                logger.info(f"OpenAI client initialized with model: {self.model}")

            elif self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
                logger.info(f"Anthropic client initialized with model: {self.model}")

            elif self.provider == "google":
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
                logger.info(f"Google Gemini client initialized with model: {self.model}")

            else:
                logger.warning(f"Unknown AI provider: {self.provider} - falling back to mock")
                self.provider = "mock"

        except ImportError as e:
            logger.warning(f"Failed to import {self.provider} client: {e} - falling back to mock")
            self.provider = "mock"
        except Exception as e:
            logger.error(f"Failed to initialize AI client: {e}")
            self.provider = "mock"

    # ================================================================
    # Analysis Methods
    # ================================================================

    async def analyze_finding(self, finding_id: UUID) -> AIAnalysis:
        """
        Analyze a single finding using AI.

        Args:
            finding_id: ID of the finding to analyze

        Returns:
            AIAnalysis: The AI analysis record

        Raises:
            HTTPException: If finding not found
        """
        # Get the finding
        finding = self.db.query(Finding).filter(
            Finding.id == finding_id
        ).first()

        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found"
            )

        # Check if analysis already exists
        existing = self.db.query(AIAnalysis).filter(
            AIAnalysis.finding_id == finding_id
        ).first()

        if existing and existing.status == "completed":
            return existing

        # Create analysis record
        analysis = AIAnalysis(
            finding_id=finding_id,
            scan_id=finding.scan_id,
            status="pending",
            provider=self.provider,
            model=self.model,
        )

        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)

        # Run the analysis
        try:
            result = await self._run_analysis(finding, analysis)
            self._update_analysis(analysis, result)
        except Exception as e:
            analysis.status = "failed"
            analysis.error_message = str(e)
            self.db.commit()
            raise

        return analysis

    async def analyze_scan_findings(self, scan_id: UUID, user_id: UUID) -> List[AIAnalysis]:
        """
        Analyze all findings for a scan.

        Args:
            scan_id: ID of the scan
            user_id: ID of the user (for authorization)

        Returns:
            List[AIAnalysis]: List of analysis records
        """
        # Verify scan exists
        scan = self.db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == user_id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )

        # Get all findings
        findings = self.db.query(Finding).filter(
            Finding.scan_id == scan_id
        ).all()

        if not findings:
            return []

        # Analyze each finding
        analyses = []
        for finding in findings:
            analysis = await self.analyze_finding(finding.id)
            analyses.append(analysis)

        return analyses

    async def _run_analysis(self, finding: Finding, analysis: AIAnalysis) -> Dict[str, Any]:
        """
        Run the AI analysis on a finding.

        Args:
            finding: The finding to analyze
            analysis: The analysis record

        Returns:
            Dict[str, Any]: Analysis results
        """
        # Mark as processing
        analysis.status = "processing"
        self.db.commit()

        # Build prompt
        prompt = self._build_prompt(finding)

        try:
            if self.provider == "mock":
                result = self._mock_analysis(finding)

            elif self.provider == "openai":
                result = await self._analyze_with_openai(prompt)

            elif self.provider == "anthropic":
                result = await self._analyze_with_anthropic(prompt)

            elif self.provider == "google":
                result = await self._analyze_with_google(prompt)

            else:
                result = self._mock_analysis(finding)

            return result

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            raise

    def _build_prompt(self, finding: Finding) -> str:
        """
        Build the prompt for AI analysis.

        Args:
            finding: The finding to analyze

        Returns:
            str: The prompt
        """
        prompt = f"""
You are a cybersecurity expert analyzing a security finding.

**Finding Details:**
- Title: {finding.title}
- Severity: {finding.severity.upper()}
- Category: {finding.category}
- Description: {finding.description}
- Confidence: {finding.confidence}

Please provide a comprehensive analysis with the following sections:

1. **Plain Explanation** (2-3 sentences for a non-technical business owner)
2. **Risk Explanation** (What are the risks if this is exploited?)
3. **Technical Explanation** (For developers - what's actually happening?)
4. **Business Impact** (How does this affect the business?)
5. **Recommended Remediation** (Step-by-step fix for developers)
6. **Priority** (Critical/High/Medium/Low based on real-world risk)

Format your response as JSON with these keys:
- plain_explanation
- risk_explanation
- technical_explanation
- business_impact
- recommended_remediation
- priority

Be specific, accurate, and practical. Do not invent vulnerabilities or overstate risks.
"""
        return prompt

    async def _analyze_with_openai(self, prompt: str) -> Dict[str, Any]:
        """Analyze using OpenAI."""
        if not self._client:
            raise ValueError("OpenAI client not initialized")

        try:
            response = self._client.chat.completions.create(
                model=self.model or "gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=settings.AI_TEMPERATURE,
                max_tokens=settings.AI_MAX_TOKENS,
            )

            content = response.choices[0].message.content
            # Parse JSON from response
            return self._parse_analysis_response(content)

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise

    async def _analyze_with_anthropic(self, prompt: str) -> Dict[str, Any]:
        """Analyze using Anthropic Claude."""
        if not self._client:
            raise ValueError("Anthropic client not initialized")

        try:
            response = self._client.messages.create(
                model=self.model or "claude-3-opus-20240229",
                max_tokens=settings.AI_MAX_TOKENS,
                temperature=settings.AI_TEMPERATURE,
                system="You are a cybersecurity expert. Respond with valid JSON only.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            content = response.content[0].text
            return self._parse_analysis_response(content)

        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise

    async def _analyze_with_google(self, prompt: str) -> Dict[str, Any]:
        """Analyze using Google Gemini."""
        if not self._client:
            raise ValueError("Google Gemini client not initialized")

        try:
            response = self._client.generate_content(
                prompt + "\n\nRespond with valid JSON only.",
                generation_config={
                    "temperature": settings.AI_TEMPERATURE,
                    "max_output_tokens": settings.AI_MAX_TOKENS,
                }
            )

            content = response.text
            return self._parse_analysis_response(content)

        except Exception as e:
            logger.error(f"Google Gemini API error: {e}")
            raise

    def _parse_analysis_response(self, content: str) -> Dict[str, Any]:
        """
        Parse the AI response and extract JSON.

        Args:
            content: The AI response text

        Returns:
            Dict[str, Any]: Parsed analysis data
        """
        try:
            # Try to find JSON in the response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Try parsing the whole response
                return json.loads(content)
        except json.JSONDecodeError:
            # Fallback: extract fields manually or return mock
            logger.warning("Failed to parse AI response as JSON")
            return {
                "plain_explanation": content[:200] + "..." if len(content) > 200 else content,
                "risk_explanation": "Unable to parse AI response.",
                "technical_explanation": "Unable to parse AI response.",
                "business_impact": "Unable to parse AI response.",
                "recommended_remediation": "Please review the finding manually.",
                "priority": "medium",
            }

    def _mock_analysis(self, finding: Finding) -> Dict[str, Any]:
        """
        Generate a mock analysis for testing.

        Args:
            finding: The finding to analyze

        Returns:
            Dict[str, Any]: Mock analysis results
        """
        severity_descriptions = {
            "critical": "This is a critical security issue that requires immediate attention. Attackers can exploit this to compromise your entire system.",
            "high": "This is a high-severity issue that should be addressed soon. It could lead to significant security breaches.",
            "medium": "This is a medium-severity issue that should be addressed in the near future. It could expose sensitive information or allow limited attacks.",
            "low": "This is a low-severity issue. While it poses some risk, it is unlikely to be exploited or cause significant damage.",
            "info": "This is informational and does not pose an immediate security risk, but may indicate best practices that could be improved.",
        }

        return {
            "plain_explanation": f"Your website has a {finding.severity} issue related to {finding.category}: {finding.title}.",
            "risk_explanation": severity_descriptions.get(finding.severity, "This issue poses some security risk."),
            "technical_explanation": f"This finding was detected by the {finding.scanner_module} scanner. {finding.description[:200]}",
            "business_impact": f"This {finding.severity} issue could affect your business by exposing sensitive data, damaging your reputation, or violating compliance requirements.",
            "recommended_remediation": "Address this issue by following security best practices. Review your configuration, update your software, and implement proper security controls.",
            "priority": finding.severity,
        }

    def _update_analysis(self, analysis: AIAnalysis, result: Dict[str, Any]) -> None:
        """
        Update the analysis record with results.

        Args:
            analysis: The analysis record
            result: The analysis results
        """
        analysis.status = "completed"
        analysis.plain_explanation = result.get("plain_explanation")
        analysis.risk_explanation = result.get("risk_explanation")
        analysis.technical_explanation = result.get("technical_explanation")
        analysis.business_impact = result.get("business_impact")
        analysis.recommended_remediation = result.get("recommended_remediation")
        analysis.developer_remediation = result.get("developer_remediation", result.get("recommended_remediation"))
        analysis.priority = result.get("priority", "medium")
        analysis.confidence = result.get("confidence", 0.85)
        analysis.references = result.get("references", [])
        analysis.completed_at = datetime.utcnow()

        self.db.commit()

    # ================================================================
    # Analysis Retrieval
    # ================================================================

    def get_analysis_for_finding(self, finding_id: UUID) -> Optional[AIAnalysis]:
        """
        Get the AI analysis for a finding.

        Args:
            finding_id: ID of the finding

        Returns:
            Optional[AIAnalysis]: The analysis or None
        """
        return self.db.query(AIAnalysis).filter(
            AIAnalysis.finding_id == finding_id
        ).first()

    def get_analyses_for_scan(self, scan_id: UUID) -> List[AIAnalysis]:
        """
        Get all AI analyses for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            List[AIAnalysis]: List of analyses
        """
        return self.db.query(AIAnalysis).filter(
            AIAnalysis.scan_id == scan_id
        ).order_by(
            AIAnalysis.created_at.desc()
        ).all()

    def get_analysis_status(self, scan_id: UUID) -> Dict[str, Any]:
        """
        Get the status of AI analysis for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            Dict[str, Any]: Analysis status
        """
        analyses = self.get_analyses_for_scan(scan_id)

        if not analyses:
            return {
                "total": 0,
                "pending": 0,
                "processing": 0,
                "completed": 0,
                "failed": 0,
                "status": "not_started",
            }

        status_counts = {
            "pending": 0,
            "processing": 0,
            "completed": 0,
            "failed": 0,
        }

        for analysis in analyses:
            if analysis.status in status_counts:
                status_counts[analysis.status] += 1

        overall_status = "completed" if status_counts["completed"] == len(analyses) else "in_progress"

        return {
            "total": len(analyses),
            "pending": status_counts["pending"],
            "processing": status_counts["processing"],
            "completed": status_counts["completed"],
            "failed": status_counts["failed"],
            "status": overall_status,
            "provider": self.provider,
            "model": self.model,
        }

    # ================================================================
    # Helper Methods
    # ================================================================

    def is_available(self) -> bool:
        """
        Check if AI service is available.

        Returns:
            bool: True if AI service is available
        """
        return self.provider != "mock" and self.api_key is not None

    def get_provider_info(self) -> Dict[str, str]:
        """
        Get information about the AI provider.

        Returns:
            Dict[str, str]: Provider information
        """
        return {
            "provider": self.provider or "not_configured",
            "model": self.model or "default",
            "available": str(self.is_available()),
        }


# Need to import datetime at the top
from datetime import datetime