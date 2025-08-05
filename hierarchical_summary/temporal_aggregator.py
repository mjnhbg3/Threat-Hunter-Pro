"""
Temporal aggregator for progressive summarization across time periods.

This module handles the aggregation of lower-level summaries into higher-level
time-based summaries, building insights progressively from cluster -> daily ->
weekly -> monthly -> quarterly. It implements intelligent aggregation algorithms
that preserve key insights while identifying trends and patterns across time.
"""

import asyncio
import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime, date, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass
import calendar

from ..ai_logic import get_ai_response
from .models import (
    ClusterSummary, DailySummary, WeeklySummary, MonthlySummary, QuarterlySummary,
    SecurityTrend, EntityActivity, SecurityPattern, SummaryMetadata, SummaryLevel,
    SummaryConfig
)

logger = logging.getLogger(__name__)


@dataclass
class AggregationContext:
    """Context information for aggregation operations."""
    time_range_start: datetime
    time_range_end: datetime
    source_summaries: List[Any]  # Can be any summary type
    target_level: SummaryLevel
    parent_context: Optional['AggregationContext'] = None


class TemporalAggregator:
    """Handles temporal aggregation of summaries across different time granularities."""
    
    def __init__(self, config: SummaryConfig):
        self.config = config
        self.trend_analyzer = TrendAnalyzer()
        self.entity_tracker = EntityTracker()
        self.pattern_aggregator = PatternAggregator()
        
    async def initialize(self):
        """Initialize the temporal aggregator."""
        await self.trend_analyzer.initialize()
        await self.entity_tracker.initialize()
        await self.pattern_aggregator.initialize()
        logger.info("TemporalAggregator initialized")
        
    async def aggregate_to_daily(self, cluster_summaries: List[ClusterSummary], 
                                target_date: date) -> DailySummary:
        """
        Aggregate cluster summaries into a daily summary.
        
        Args:
            cluster_summaries: List of cluster summaries for the day
            target_date: Date for the daily summary
            
        Returns:
            DailySummary object
        """
        start_time = datetime.utcnow()
        
        if not cluster_summaries:
            return await self._create_empty_daily_summary(target_date)
            
        # Create aggregation context
        day_start = datetime.combine(target_date, datetime.min.time())
        day_end = day_start + timedelta(days=1) - timedelta(microseconds=1)
        
        context = AggregationContext(
            time_range_start=day_start,
            time_range_end=day_end,
            source_summaries=cluster_summaries,
            target_level=SummaryLevel.DAILY
        )
        
        # Aggregate security trends
        daily_trends = await self.trend_analyzer.analyze_daily_trends(cluster_summaries)
        
        # Aggregate entity activities
        top_entities = await self.entity_tracker.aggregate_daily_entities(cluster_summaries)
        
        # Aggregate patterns and calculate metrics
        incident_count = await self._calculate_incident_count(cluster_summaries)
        alert_volume = sum(len(cs.log_references) for cs in cluster_summaries)
        
        # Generate executive summary
        executive_summary = await self._generate_daily_executive_summary(
            context, daily_trends, top_entities, incident_count, alert_volume
        )
        
        # Extract key findings
        key_findings = await self._extract_daily_key_findings(cluster_summaries, daily_trends)
        
        # Calculate system health and compliance
        system_health = await self._assess_daily_system_health(cluster_summaries)
        compliance_status = await self._check_daily_compliance(cluster_summaries)
        
        # Generate recommendations
        recommendations = await self._generate_daily_recommendations(
            cluster_summaries, daily_trends, top_entities
        )
        
        # Calculate metrics
        metrics = await self._calculate_daily_metrics(cluster_summaries, daily_trends)
        
        # Create metadata
        generation_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        metadata = SummaryMetadata(
            summary_id=f"daily_{target_date.isoformat()}",
            level=SummaryLevel.DAILY,
            time_range_start=day_start,
            time_range_end=day_end,
            source_count=len(cluster_summaries),
            token_count=len(executive_summary.split()) * 1.3,
            generation_time_ms=generation_time,
            parent_summaries=[cs.metadata.summary_id for cs in cluster_summaries],
            quality_score=await self._assess_daily_quality(cluster_summaries, daily_trends),
            tags=await self._generate_daily_tags(cluster_summaries, daily_trends)
        )
        
        return DailySummary(
            metadata=metadata,
            date=target_date,
            executive_summary=executive_summary,
            key_findings=key_findings,
            security_trends=daily_trends,
            top_entities=top_entities,
            incident_count=incident_count,
            alert_volume=alert_volume,
            cluster_summaries=[cs.metadata.summary_id for cs in cluster_summaries],
            system_health=system_health,
            compliance_status=compliance_status,
            recommendations=recommendations,
            metrics=metrics
        )
        
    async def aggregate_to_weekly(self, daily_summaries: List[DailySummary], 
                                 week_start: date) -> WeeklySummary:
        """
        Aggregate daily summaries into a weekly summary.
        
        Args:
            daily_summaries: List of daily summaries for the week
            week_start: Start date of the week
            
        Returns:
            WeeklySummary object
        """
        start_time = datetime.utcnow()
        week_end = week_start + timedelta(days=6)
        
        if not daily_summaries:
            return await self._create_empty_weekly_summary(week_start, week_end)
            
        # Create aggregation context
        context = AggregationContext(
            time_range_start=datetime.combine(week_start, datetime.min.time()),
            time_range_end=datetime.combine(week_end, datetime.max.time()),
            source_summaries=daily_summaries,
            target_level=SummaryLevel.WEEKLY
        )
        
        # Aggregate weekly trends with week-over-week comparison
        weekly_trends = await self.trend_analyzer.analyze_weekly_trends(daily_summaries)
        
        # Identify major incidents
        major_incidents = await self._identify_major_incidents(daily_summaries)
        
        # Analyze entity behaviors across the week
        entity_behaviors = await self.entity_tracker.analyze_weekly_behaviors(daily_summaries)
        
        # Detect attack campaigns
        campaigns = await self.pattern_aggregator.detect_campaigns(daily_summaries, week_start, week_end)
        
        # Generate executive summary
        executive_summary = await self._generate_weekly_executive_summary(
            context, weekly_trends, major_incidents, entity_behaviors
        )
        
        # Week-over-week comparison (if previous week data available)
        week_comparison = await self._perform_week_over_week_comparison(daily_summaries, week_start)
        
        # Generate insights
        infrastructure_insights = await self._extract_infrastructure_insights(daily_summaries)
        user_behavior_insights = await self._extract_user_behavior_insights(daily_summaries)
        threat_landscape = await self._analyze_threat_landscape(daily_summaries, weekly_trends)
        
        # Strategic recommendations
        strategic_recommendations = await self._generate_strategic_recommendations(
            weekly_trends, major_incidents, entity_behaviors
        )
        
        # Create metadata
        generation_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        metadata = SummaryMetadata(
            summary_id=f"weekly_{week_start.isoformat()}",
            level=SummaryLevel.WEEKLY,
            time_range_start=context.time_range_start,
            time_range_end=context.time_range_end,
            source_count=len(daily_summaries),
            token_count=len(executive_summary.split()) * 1.3,
            generation_time_ms=generation_time,
            parent_summaries=[ds.metadata.summary_id for ds in daily_summaries],
            quality_score=await self._assess_weekly_quality(daily_summaries, weekly_trends),
            tags=await self._generate_weekly_tags(daily_summaries, weekly_trends)
        )
        
        return WeeklySummary(
            metadata=metadata,
            week_start=week_start,
            week_end=week_end,
            executive_summary=executive_summary,
            weekly_trends=weekly_trends,
            major_incidents=major_incidents,
            entity_behavior_analysis=entity_behaviors,
            campaign_detection=campaigns,
            daily_summaries=[ds.metadata.summary_id for ds in daily_summaries],
            week_over_week_comparison=week_comparison,
            infrastructure_insights=infrastructure_insights,
            user_behavior_insights=user_behavior_insights,
            threat_landscape=threat_landscape,
            strategic_recommendations=strategic_recommendations
        )
        
    async def aggregate_to_monthly(self, weekly_summaries: List[WeeklySummary], 
                                  month: int, year: int) -> MonthlySummary:
        """
        Aggregate weekly summaries into a monthly summary.
        
        Args:
            weekly_summaries: List of weekly summaries for the month
            month: Month number (1-12)
            year: Year
            
        Returns:
            MonthlySummary object
        """
        start_time = datetime.utcnow()
        
        if not weekly_summaries:
            return await self._create_empty_monthly_summary(month, year)
            
        # Create aggregation context
        month_start = datetime(year, month, 1)
        month_end = datetime(year, month, calendar.monthrange(year, month)[1], 23, 59, 59)
        
        context = AggregationContext(
            time_range_start=month_start,
            time_range_end=month_end,
            source_summaries=weekly_summaries,
            target_level=SummaryLevel.MONTHLY
        )
        
        # Aggregate monthly trends
        monthly_trends = await self.trend_analyzer.analyze_monthly_trends(weekly_summaries)
        
        # Security posture assessment
        security_posture = await self._assess_monthly_security_posture(weekly_summaries)
        
        # Threat intelligence aggregation
        threat_intelligence = await self._aggregate_threat_intelligence(weekly_summaries)
        
        # Month-over-month analysis
        month_comparison = await self._perform_month_over_month_analysis(weekly_summaries, month, year)
        
        # Infrastructure assessment
        infrastructure_assessment = await self._assess_monthly_infrastructure(weekly_summaries)
        
        # Policy effectiveness analysis
        policy_effectiveness = await self._analyze_policy_effectiveness(weekly_summaries)
        
        # Budget impact analysis
        budget_impact = await self._analyze_budget_impact(weekly_summaries)
        
        # Compliance scorecard
        compliance_scorecard = await self._generate_compliance_scorecard(weekly_summaries)
        
        # Strategic initiatives
        strategic_initiatives = await self._recommend_strategic_initiatives(
            monthly_trends, security_posture, threat_intelligence
        )
        
        # Executive KPIs
        executive_kpis = await self._calculate_executive_kpis(weekly_summaries)
        
        # Generate executive summary
        executive_summary = await self._generate_monthly_executive_summary(
            context, monthly_trends, security_posture, strategic_initiatives
        )
        
        # Create metadata
        generation_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        metadata = SummaryMetadata(
            summary_id=f"monthly_{year}_{month:02d}",
            level=SummaryLevel.MONTHLY,
            time_range_start=month_start,
            time_range_end=month_end,
            source_count=len(weekly_summaries),
            token_count=len(executive_summary.split()) * 1.3,
            generation_time_ms=generation_time,
            parent_summaries=[ws.metadata.summary_id for ws in weekly_summaries],
            quality_score=await self._assess_monthly_quality(weekly_summaries, monthly_trends),
            tags=await self._generate_monthly_tags(weekly_summaries, monthly_trends)
        )
        
        return MonthlySummary(
            metadata=metadata,
            month=month,
            year=year,
            executive_summary=executive_summary,
            security_posture_assessment=security_posture,
            monthly_trends=monthly_trends,
            threat_intelligence=threat_intelligence,
            weekly_summaries=[ws.metadata.summary_id for ws in weekly_summaries],
            month_over_month_analysis=month_comparison,
            infrastructure_assessment=infrastructure_assessment,
            policy_effectiveness=policy_effectiveness,
            budget_impact_analysis=budget_impact,
            compliance_scorecard=compliance_scorecard,
            strategic_initiatives=strategic_initiatives,
            executive_kpis=executive_kpis
        )
        
    async def aggregate_to_quarterly(self, monthly_summaries: List[MonthlySummary], 
                                   quarter: int, year: int) -> QuarterlySummary:
        """
        Aggregate monthly summaries into a quarterly summary.
        
        Args:
            monthly_summaries: List of monthly summaries for the quarter
            quarter: Quarter number (1-4)
            year: Year
            
        Returns:
            QuarterlySummary object
        """
        start_time = datetime.utcnow()
        
        if not monthly_summaries:
            return await self._create_empty_quarterly_summary(quarter, year)
            
        # Create aggregation context
        quarter_start_month = (quarter - 1) * 3 + 1
        quarter_start = datetime(year, quarter_start_month, 1)
        quarter_end_month = quarter * 3
        quarter_end = datetime(year, quarter_end_month, 
                              calendar.monthrange(year, quarter_end_month)[1], 23, 59, 59)
        
        context = AggregationContext(
            time_range_start=quarter_start,
            time_range_end=quarter_end,
            source_summaries=monthly_summaries,
            target_level=SummaryLevel.QUARTERLY
        )
        
        # Security program assessment
        program_assessment = await self._assess_security_program(monthly_summaries)
        
        # Quarterly trends
        quarterly_trends = await self.trend_analyzer.analyze_quarterly_trends(monthly_summaries)
        
        # Threat landscape evolution
        threat_evolution = await self._analyze_threat_landscape_evolution(monthly_summaries)
        
        # Quarter-over-quarter analysis
        quarter_comparison = await self._perform_quarter_over_quarter_analysis(
            monthly_summaries, quarter, year
        )
        
        # Strategic security metrics
        strategic_metrics = await self._calculate_strategic_metrics(monthly_summaries)
        
        # Investment recommendations
        investment_recommendations = await self._generate_investment_recommendations(
            program_assessment, quarterly_trends, strategic_metrics
        )
        
        # Regulatory compliance status
        regulatory_compliance = await self._assess_regulatory_compliance(monthly_summaries)
        
        # Business risk assessment
        business_risk = await self._assess_business_risk(monthly_summaries, quarterly_trends)
        
        # Board presentation highlights
        board_highlights = await self._generate_board_highlights(
            program_assessment, quarterly_trends, strategic_metrics
        )
        
        # Annual planning inputs
        annual_planning = await self._generate_annual_planning_inputs(
            quarterly_trends, investment_recommendations, business_risk
        )
        
        # Generate executive summary
        executive_summary = await self._generate_quarterly_executive_summary(
            context, program_assessment, quarterly_trends, strategic_metrics
        )
        
        # Create metadata
        generation_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        metadata = SummaryMetadata(
            summary_id=f"quarterly_{year}_Q{quarter}",
            level=SummaryLevel.QUARTERLY,
            time_range_start=quarter_start,
            time_range_end=quarter_end,
            source_count=len(monthly_summaries),
            token_count=len(executive_summary.split()) * 1.3,
            generation_time_ms=generation_time,
            parent_summaries=[ms.metadata.summary_id for ms in monthly_summaries],
            quality_score=await self._assess_quarterly_quality(monthly_summaries, quarterly_trends),
            tags=await self._generate_quarterly_tags(monthly_summaries, quarterly_trends)
        )
        
        return QuarterlySummary(
            metadata=metadata,
            quarter=quarter,
            year=year,
            executive_summary=executive_summary,
            security_program_assessment=program_assessment,
            quarterly_trends=quarterly_trends,
            threat_landscape_evolution=threat_evolution,
            monthly_summaries=[ms.metadata.summary_id for ms in monthly_summaries],
            quarter_over_quarter_analysis=quarter_comparison,
            strategic_security_metrics=strategic_metrics,
            investment_recommendations=investment_recommendations,
            regulatory_compliance_status=regulatory_compliance,
            business_risk_assessment=business_risk,
            board_presentation_highlights=board_highlights,
            annual_planning_inputs=annual_planning
        )
        
    # Daily aggregation helper methods
    async def _create_empty_daily_summary(self, target_date: date) -> DailySummary:
        """Create an empty daily summary for days with no cluster summaries."""
        day_start = datetime.combine(target_date, datetime.min.time())
        day_end = day_start + timedelta(days=1) - timedelta(microseconds=1)
        
        metadata = SummaryMetadata(
            summary_id=f"daily_{target_date.isoformat()}",
            level=SummaryLevel.DAILY,
            time_range_start=day_start,
            time_range_end=day_end,
            source_count=0,
            token_count=100,  # Estimated for empty summary
            generation_time_ms=0,
            quality_score=1.0,  # Perfect quality for no events
            tags={"quiet_day", "no_incidents"}
        )
        
        return DailySummary(
            metadata=metadata,
            date=target_date,
            executive_summary=f"No significant security events detected on {target_date.isoformat()}. All monitored systems remained quiet with no alerts or incidents requiring attention.",
            key_findings=["No security incidents detected"],
            security_trends=[],
            top_entities=[],
            incident_count=0,
            alert_volume=0,
            cluster_summaries=[],
            system_health={"status": "healthy", "monitored_systems": 0},
            compliance_status={"overall": "compliant"},
            recommendations=["Continue monitoring", "Verify system connectivity"],
            metrics={"incidents": 0, "alerts": 0, "entities": 0}
        )
        
    async def _calculate_incident_count(self, cluster_summaries: List[ClusterSummary]) -> int:
        """Calculate the number of security incidents from cluster summaries."""
        incident_count = 0
        
        for cluster in cluster_summaries:
            # Count high and critical severity patterns as incidents
            for pattern in cluster.security_patterns:
                if pattern.severity in ["high", "critical"]:
                    incident_count += 1
                    
            # Count clusters with high risk assessment as incidents
            if cluster.risk_assessment in ["high", "critical"]:
                incident_count += 1
                
        return incident_count
        
    async def _assess_daily_system_health(self, cluster_summaries: List[ClusterSummary]) -> Dict[str, Any]:
        """Assess system health based on daily cluster summaries."""
        system_health = {
            "status": "healthy",
            "monitored_systems": 0,
            "unhealthy_systems": [],
            "performance_issues": [],
            "connectivity_issues": []
        }
        
        # Collect affected systems
        all_systems = set()
        problematic_systems = set()
        
        for cluster in cluster_summaries:
            systems = cluster.common_elements.get("affected_systems", [])
            all_systems.update(systems)
            
            # Systems with high-risk patterns are considered problematic
            if cluster.risk_assessment in ["high", "critical"]:
                problematic_systems.update(systems)
                
        system_health["monitored_systems"] = len(all_systems)
        system_health["unhealthy_systems"] = list(problematic_systems)
        
        # Determine overall status
        if len(problematic_systems) > len(all_systems) * 0.5:
            system_health["status"] = "degraded"
        elif len(problematic_systems) > len(all_systems) * 0.2:
            system_health["status"] = "warning"
            
        return system_health
        
    async def _check_daily_compliance(self, cluster_summaries: List[ClusterSummary]) -> Dict[str, str]:
        """Check compliance status based on daily activities."""
        compliance_status = {
            "overall": "compliant",
            "authentication": "compliant",
            "access_control": "compliant",
            "data_protection": "compliant",
            "audit_logging": "compliant"
        }
        
        # Check for compliance violations in cluster patterns
        for cluster in cluster_summaries:
            for pattern in cluster.security_patterns:
                if "authentication" in pattern.description.lower():
                    if pattern.severity in ["high", "critical"]:
                        compliance_status["authentication"] = "violation"
                        compliance_status["overall"] = "non_compliant"
                        
                if "access" in pattern.description.lower():
                    if pattern.severity in ["high", "critical"]:
                        compliance_status["access_control"] = "violation"
                        compliance_status["overall"] = "non_compliant"
                        
        return compliance_status
        
    async def _generate_daily_executive_summary(self, context: AggregationContext,
                                              trends: List[SecurityTrend],
                                              entities: List[EntityActivity],
                                              incident_count: int,
                                              alert_volume: int) -> str:
        """Generate executive summary for daily summary using AI."""
        
        # Prepare context for AI
        summary_context = {
            "date": context.time_range_start.date().isoformat(),
            "cluster_count": len(context.source_summaries),
            "incident_count": incident_count,
            "alert_volume": alert_volume,
            "top_trends": [t.trend_name for t in trends[:3]] if trends else [],
            "top_entities": [f"{e.entity} ({e.entity_type})" for e in entities[:3]] if entities else [],
            "risk_levels": [cs.risk_assessment for cs in context.source_summaries]
        }
        
        # Create AI prompt
        prompt = f"""
        Generate an executive summary for security activities on {summary_context['date']}.

        Key Statistics:
        - {summary_context['cluster_count']} security event clusters analyzed
        - {incident_count} security incidents identified
        - {alert_volume} total security alerts processed
        - Top security trends: {', '.join(summary_context['top_trends']) if summary_context['top_trends'] else 'None significant'}
        - Most active entities: {', '.join(summary_context['top_entities']) if summary_context['top_entities'] else 'None significant'}

        Provide a 3-4 sentence executive summary that:
        1. Summarizes the overall security posture for the day
        2. Highlights any significant security events or trends
        3. Provides a risk assessment and outlook
        4. Mentions any notable entity activities

        Keep it executive-level, concise, and focused on business impact.
        """
        
        try:
            response = await get_ai_response(prompt, model="flash")
            if response and len(response) > 100:
                return response.strip()
        except Exception as e:
            logger.warning(f"AI executive summary generation failed: {e}")
            
        # Fallback template-based summary
        return self._generate_daily_template_summary(summary_context)
        
    def _generate_daily_template_summary(self, context: Dict[str, Any]) -> str:
        """Generate template-based daily summary as fallback."""
        summary_parts = []
        
        if context['incident_count'] == 0:
            summary_parts.append(f"Security operations on {context['date']} remained stable with no critical incidents detected.")
        else:
            summary_parts.append(f"Security operations on {context['date']} identified {context['incident_count']} incidents requiring attention.")
            
        summary_parts.append(f"Analyzed {context['cluster_count']} event clusters from {context['alert_volume']} total alerts.")
        
        if context['top_trends']:
            summary_parts.append(f"Key security trends observed: {', '.join(context['top_trends'])}.")
            
        if context['top_entities']:
            summary_parts.append(f"Notable entity activity from: {', '.join(context['top_entities'])}.")
        else:
            summary_parts.append("Entity activity levels remained within normal parameters.")
            
        return " ".join(summary_parts)
        
    async def _extract_daily_key_findings(self, cluster_summaries: List[ClusterSummary],
                                        trends: List[SecurityTrend]) -> List[str]:
        """Extract key findings from daily cluster summaries."""
        findings = []
        
        # Findings from high-risk clusters
        high_risk_clusters = [cs for cs in cluster_summaries if cs.risk_assessment in ["high", "critical"]]
        for cluster in high_risk_clusters[:3]:  # Top 3 high-risk clusters
            findings.append(f"High-risk security cluster: {cluster.summary_text[:100]}...")
            
        # Findings from trends
        for trend in trends[:3]:  # Top 3 trends
            if trend.significance == "high":
                findings.append(f"Significant trend detected: {trend.trend_name} - {trend.direction}")
                
        # Findings from patterns
        all_patterns = []
        for cluster in cluster_summaries:
            all_patterns.extend(cluster.security_patterns)
            
        # Group patterns by type
        pattern_counts = Counter(p.pattern_type for p in all_patterns)
        for pattern_type, count in pattern_counts.most_common(3):
            if count >= 2:
                findings.append(f"Multiple {pattern_type} patterns detected ({count} occurrences)")
                
        return findings[:5]  # Limit to top 5 findings
        
    async def _calculate_daily_metrics(self, cluster_summaries: List[ClusterSummary],
                                     trends: List[SecurityTrend]) -> Dict[str, float]:
        """Calculate daily security metrics."""
        metrics = {}
        
        # Basic counts
        metrics["total_clusters"] = len(cluster_summaries)
        metrics["total_logs"] = sum(len(cs.log_references) for cs in cluster_summaries)
        metrics["unique_entities"] = len(set(
            entity.entity for cs in cluster_summaries for entity in cs.entity_activities
        ))
        
        # Risk metrics
        risk_scores = []
        for cs in cluster_summaries:
            if cs.risk_assessment == "critical":
                risk_scores.append(1.0)
            elif cs.risk_assessment == "high":
                risk_scores.append(0.8)
            elif cs.risk_assessment == "medium":
                risk_scores.append(0.6)
            else:
                risk_scores.append(0.3)
                
        metrics["avg_risk_score"] = np.mean(risk_scores) if risk_scores else 0.0
        metrics["max_risk_score"] = max(risk_scores) if risk_scores else 0.0
        
        # Pattern metrics
        all_patterns = [p for cs in cluster_summaries for p in cs.security_patterns]
        metrics["total_patterns"] = len(all_patterns)
        metrics["critical_patterns"] = len([p for p in all_patterns if p.severity == "critical"])
        
        # Trend metrics
        metrics["trend_count"] = len(trends)
        metrics["increasing_trends"] = len([t for t in trends if t.direction == "increasing"])
        metrics["decreasing_trends"] = len([t for t in trends if t.direction == "decreasing"])
        
        return metrics
        
    # Weekly aggregation helper methods
    async def _create_empty_weekly_summary(self, week_start: date, week_end: date) -> WeeklySummary:
        """Create an empty weekly summary for weeks with no daily summaries."""
        start_dt = datetime.combine(week_start, datetime.min.time())
        end_dt = datetime.combine(week_end, datetime.max.time())
        
        metadata = SummaryMetadata(
            summary_id=f"weekly_{week_start.isoformat()}",
            level=SummaryLevel.WEEKLY,
            time_range_start=start_dt,
            time_range_end=end_dt,
            source_count=0,
            token_count=150,
            generation_time_ms=0,
            quality_score=1.0,
            tags={"quiet_week", "no_incidents"}
        )
        
        return WeeklySummary(
            metadata=metadata,
            week_start=week_start,
            week_end=week_end,
            executive_summary=f"Week of {week_start.isoformat()} to {week_end.isoformat()} showed minimal security activity with no significant incidents or trends detected.",
            weekly_trends=[],
            major_incidents=[],
            entity_behavior_analysis=[],
            campaign_detection=[],
            daily_summaries=[],
            week_over_week_comparison={"status": "no_data"},
            infrastructure_insights=["No infrastructure issues detected"],
            user_behavior_insights=["User activity levels normal"],
            threat_landscape={"overall_threat_level": "low"},
            strategic_recommendations=["Continue monitoring", "Maintain current security posture"]
        )
        
    async def _identify_major_incidents(self, daily_summaries: List[DailySummary]) -> List[Dict[str, Any]]:
        """Identify major security incidents from daily summaries."""
        major_incidents = []
        
        for daily in daily_summaries:
            # Incidents with high incident count
            if daily.incident_count >= 5:
                major_incidents.append({
                    "date": daily.date.isoformat(),
                    "type": "high_incident_volume",
                    "description": f"High incident volume: {daily.incident_count} incidents",
                    "severity": "high" if daily.incident_count >= 10 else "medium",
                    "entities_involved": len(daily.top_entities),
                    "trends_identified": len(daily.security_trends)
                })
                
            # Incidents with critical trends
            critical_trends = [t for t in daily.security_trends if t.significance == "high"]
            if critical_trends:
                for trend in critical_trends:
                    major_incidents.append({
                        "date": daily.date.isoformat(),
                        "type": "critical_trend",
                        "description": f"Critical security trend: {trend.trend_name}",
                        "severity": "critical",
                        "trend_direction": trend.direction,
                        "confidence": trend.confidence
                    })
                    
        return major_incidents[:10]  # Limit to top 10 incidents
        
    # Monthly and Quarterly helper methods would continue in similar pattern...
    # For brevity, I'll include key methods and patterns
    
    async def _assess_quarterly_quality(self, monthly_summaries: List[MonthlySummary],
                                      trends: List[SecurityTrend]) -> float:
        """Assess the quality of quarterly summary."""
        quality_factors = []
        
        # Data completeness
        if monthly_summaries:
            completeness = len(monthly_summaries) / 3.0  # Expected 3 months per quarter
            quality_factors.append(min(1.0, completeness))
        else:
            quality_factors.append(0.0)
            
        # Trend analysis quality
        if trends:
            trend_quality = min(1.0, len(trends) / 5.0)  # Expected ~5 trends per quarter
            quality_factors.append(trend_quality)
        else:
            quality_factors.append(0.5)  # Neutral if no trends
            
        # Source quality (average of monthly summary qualities)
        if monthly_summaries:
            source_quality = np.mean([ms.metadata.quality_score for ms in monthly_summaries])
            quality_factors.append(source_quality)
        else:
            quality_factors.append(0.5)
            
        return np.mean(quality_factors) if quality_factors else 0.5
        
    async def _generate_quarterly_tags(self, monthly_summaries: List[MonthlySummary],
                                     trends: List[SecurityTrend]) -> Set[str]:
        """Generate tags for quarterly summary."""
        tags = {"quarterly", "executive"}
        
        # Time-based tags
        if monthly_summaries:
            quarter_num = (monthly_summaries[0].month - 1) // 3 + 1
            tags.add(f"Q{quarter_num}")
            tags.add(f"year_{monthly_summaries[0].year}")
            
        # Trend-based tags  
        for trend in trends:
            tags.add(trend.category)
            if trend.significance == "high":
                tags.add("high_significance")
                
        # Volume-based tags
        total_source_count = sum(ms.metadata.source_count for ms in monthly_summaries)
        if total_source_count > 1000:
            tags.add("high_volume")
        elif total_source_count < 100:
            tags.add("low_volume")
            
        return tags


class TrendAnalyzer:
    """Analyzes trends across different time periods."""
    
    async def initialize(self):
        """Initialize the trend analyzer."""
        pass
        
    async def analyze_daily_trends(self, cluster_summaries: List[ClusterSummary]) -> List[SecurityTrend]:
        """Analyze trends within a single day."""
        trends = []
        
        # Pattern frequency trends
        pattern_counts = Counter()
        for cluster in cluster_summaries:
            for pattern in cluster.security_patterns:
                pattern_counts[pattern.pattern_type] += 1
                
        for pattern_type, count in pattern_counts.most_common(5):
            if count >= 2:
                trend = SecurityTrend(
                    trend_name=f"{pattern_type.title()} Pattern Frequency",
                    category="attack_patterns",
                    direction="increasing" if count > 3 else "stable",
                    magnitude=count,
                    confidence=min(1.0, count / 10.0),
                    time_period="daily",
                    significance="high" if count > 5 else "medium"
                )
                trends.append(trend)
                
        return trends
        
    async def analyze_weekly_trends(self, daily_summaries: List[DailySummary]) -> List[SecurityTrend]:
        """Analyze trends across a week."""
        trends = []
        
        # Incident volume trend
        incident_counts = [ds.incident_count for ds in daily_summaries]
        if len(incident_counts) > 1:
            trend_direction = self._analyze_trend_direction(incident_counts)
            if trend_direction != "stable":
                trend = SecurityTrend(
                    trend_name="Incident Volume Trend",
                    category="incident_patterns",
                    direction=trend_direction,
                    magnitude=max(incident_counts) - min(incident_counts),
                    confidence=0.8,
                    time_period="weekly",
                    data_points=[{"day": i, "count": count} for i, count in enumerate(incident_counts)],
                    significance="high" if max(incident_counts) > 10 else "medium"
                )
                trends.append(trend)
                
        return trends
        
    async def analyze_monthly_trends(self, weekly_summaries: List[WeeklySummary]) -> List[SecurityTrend]:
        """Analyze trends across a month."""
        trends = []
        
        # Entity behavior trends
        all_entities = {}
        for week in weekly_summaries:
            for entity_behavior in week.entity_behavior_analysis:
                entity_id = entity_behavior.entity
                if entity_id not in all_entities:
                    all_entities[entity_id] = []
                all_entities[entity_id].append(entity_behavior.activity_score)
                
        # Analyze entity activity trends
        for entity_id, scores in all_entities.items():
            if len(scores) > 1:
                direction = self._analyze_trend_direction(scores)
                if direction != "stable":
                    trend = SecurityTrend(
                        trend_name=f"Entity Activity Trend: {entity_id}",
                        category="entity_behavior",
                        direction=direction,
                        magnitude=abs(max(scores) - min(scores)),
                        confidence=0.7,
                        time_period="monthly",
                        significance="medium"
                    )
                    trends.append(trend)
                    
        return trends[:10]  # Limit to top 10 trends
        
    async def analyze_quarterly_trends(self, monthly_summaries: List[MonthlySummary]) -> List[SecurityTrend]:
        """Analyze trends across a quarter."""
        trends = []
        
        # Strategic metric trends
        if len(monthly_summaries) >= 2:
            # Analyze executive KPI trends
            kpi_trends = {}
            for monthly in monthly_summaries:
                for kpi, value in monthly.executive_kpis.items():
                    if kpi not in kpi_trends:
                        kpi_trends[kpi] = []
                    kpi_trends[kpi].append(value)
                    
            for kpi, values in kpi_trends.items():
                if len(values) > 1:
                    direction = self._analyze_trend_direction(values)
                    if direction != "stable":
                        trend = SecurityTrend(
                            trend_name=f"Strategic KPI Trend: {kpi}",
                            category="strategic_metrics",
                            direction=direction,
                            magnitude=abs(max(values) - min(values)),
                            confidence=0.8,
                            time_period="quarterly",
                            significance="high"
                        )
                        trends.append(trend)
                        
        return trends
        
    def _analyze_trend_direction(self, values: List[float]) -> str:
        """Analyze the direction of a trend from a series of values."""
        if len(values) < 2:
            return "stable"
            
        # Calculate trend using simple linear regression slope
        x = list(range(len(values)))
        y = values
        
        n = len(values)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x[i] * y[i] for i in range(n))
        sum_x2 = sum(x[i] ** 2 for i in range(n))
        
        # Calculate slope
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
        
        # Determine direction based on slope
        if abs(slope) < 0.1:  # Threshold for stability
            return "stable"
        elif slope > 0:
            return "increasing"
        else:
            return "decreasing"


class EntityTracker:
    """Tracks entity activities and behaviors across time periods."""
    
    async def initialize(self):
        """Initialize the entity tracker."""
        pass
        
    async def aggregate_daily_entities(self, cluster_summaries: List[ClusterSummary]) -> List[EntityActivity]:
        """Aggregate entity activities from cluster summaries into daily view."""
        entity_aggregates = defaultdict(lambda: {
            'total_activity': 0.0,
            'total_events': 0,
            'total_rules': set(),
            'entity_type': 'unknown',
            'first_seen': None,
            'last_seen': None,
            'behaviors': [],
            'risk_scores': []
        })
        
        # Aggregate entity data from all clusters
        for cluster in cluster_summaries:
            for entity_activity in cluster.entity_activities:
                entity_id = entity_activity.entity
                agg = entity_aggregates[entity_id]
                
                agg['total_activity'] += entity_activity.activity_score
                agg['total_events'] += entity_activity.event_count
                agg['total_rules'].update([f"rule_{entity_activity.unique_rules}"])
                agg['entity_type'] = entity_activity.entity_type
                agg['behaviors'].extend(entity_activity.top_behaviors)
                agg['risk_scores'].append(entity_activity.risk_score)
                
                # Update time bounds
                if agg['first_seen'] is None or entity_activity.first_seen < agg['first_seen']:
                    agg['first_seen'] = entity_activity.first_seen
                if agg['last_seen'] is None or entity_activity.last_seen > agg['last_seen']:
                    agg['last_seen'] = entity_activity.last_seen
                    
        # Create EntityActivity objects
        daily_entities = []
        for entity_id, agg in entity_aggregates.items():
            activity = EntityActivity(
                entity=entity_id,
                entity_type=agg['entity_type'],
                activity_score=agg['total_activity'],
                risk_score=np.mean(agg['risk_scores']) if agg['risk_scores'] else 0.0,
                event_count=agg['total_events'],
                unique_rules=len(agg['total_rules']),
                first_seen=agg['first_seen'] or datetime.utcnow(),
                last_seen=agg['last_seen'] or datetime.utcnow(),
                top_behaviors=list(set(agg['behaviors']))[:5]
            )
            daily_entities.append(activity)
            
        # Sort by activity score and return top entities
        daily_entities.sort(key=lambda x: x.activity_score, reverse=True)
        return daily_entities[:20]  # Top 20 entities
        
    async def analyze_weekly_behaviors(self, daily_summaries: List[DailySummary]) -> List[EntityActivity]:
        """Analyze entity behaviors across a week."""
        # Similar aggregation logic but across daily summaries
        entity_weekly = defaultdict(lambda: {
            'activity_scores': [],
            'total_events': 0,
            'days_active': 0,
            'behaviors': set(),
            'entity_type': 'unknown'
        })
        
        for daily in daily_summaries:
            daily_entities = {e.entity: e for e in daily.top_entities}
            
            for entity_id, entity_data in daily_entities.items():
                weekly = entity_weekly[entity_id]
                weekly['activity_scores'].append(entity_data.activity_score)
                weekly['total_events'] += entity_data.event_count
                weekly['days_active'] += 1
                weekly['behaviors'].update(entity_data.top_behaviors)
                weekly['entity_type'] = entity_data.entity_type
                
        # Convert to EntityActivity objects with weekly analysis
        weekly_behaviors = []
        for entity_id, weekly in entity_weekly.items():
            # Calculate weekly metrics
            avg_activity = np.mean(weekly['activity_scores'])
            activity_variance = np.var(weekly['activity_scores']) if len(weekly['activity_scores']) > 1 else 0
            
            # Anomaly detection: high variance indicates unusual behavior
            anomaly_indicators = []
            if activity_variance > avg_activity * 0.5:
                anomaly_indicators.append("irregular_activity_pattern")
            if weekly['days_active'] == 1:
                anomaly_indicators.append("single_day_activity")
            elif weekly['days_active'] >= 6:
                anomaly_indicators.append("persistent_activity")
                
            activity = EntityActivity(
                entity=entity_id,
                entity_type=weekly['entity_type'],
                activity_score=avg_activity,
                risk_score=min(1.0, activity_variance + (weekly['days_active'] / 7.0)),
                event_count=weekly['total_events'],
                unique_rules=len(weekly['behaviors']),  # Using behaviors as proxy
                first_seen=datetime.utcnow() - timedelta(days=6),  # Week start
                last_seen=datetime.utcnow(),  # Week end
                top_behaviors=list(weekly['behaviors'])[:5],
                anomaly_indicators=anomaly_indicators
            )
            weekly_behaviors.append(activity)
            
        weekly_behaviors.sort(key=lambda x: x.risk_score, reverse=True)
        return weekly_behaviors[:15]  # Top 15 for weekly analysis


class PatternAggregator:
    """Aggregates and analyzes security patterns across time periods."""
    
    async def initialize(self):
        """Initialize the pattern aggregator."""
        pass
        
    async def detect_campaigns(self, daily_summaries: List[DailySummary],
                             week_start: date, week_end: date) -> List[Dict[str, Any]]:
        """Detect potential attack campaigns across the week."""
        campaigns = []
        
        # Collect all patterns from the week
        all_patterns = []
        for daily in daily_summaries:
            # Extract patterns from daily trends (simplified)
            for trend in daily.security_trends:
                if trend.category == "attack_patterns":
                    all_patterns.append({
                        "date": daily.date,
                        "pattern": trend.trend_name,
                        "magnitude": trend.magnitude,
                        "confidence": trend.confidence
                    })
                    
        # Group patterns by type to identify campaigns
        pattern_groups = defaultdict(list)
        for pattern in all_patterns:
            pattern_groups[pattern["pattern"]].append(pattern)
            
        # Identify campaigns (patterns spanning multiple days)
        for pattern_type, pattern_instances in pattern_groups.items():
            if len(pattern_instances) >= 3:  # At least 3 days
                campaign = {
                    "campaign_name": f"Sustained {pattern_type}",
                    "start_date": min(p["date"] for p in pattern_instances),
                    "end_date": max(p["date"] for p in pattern_instances),
                    "duration_days": len(set(p["date"] for p in pattern_instances)),
                    "total_magnitude": sum(p["magnitude"] for p in pattern_instances),
                    "avg_confidence": np.mean([p["confidence"] for p in pattern_instances]),
                    "pattern_evolution": [
                        {"date": p["date"], "magnitude": p["magnitude"]} 
                        for p in sorted(pattern_instances, key=lambda x: x["date"])
                    ]
                }
                campaigns.append(campaign)
                
        return campaigns[:5]  # Top 5 campaigns