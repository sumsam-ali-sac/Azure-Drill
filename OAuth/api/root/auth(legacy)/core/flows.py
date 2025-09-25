"""
Authentication flow orchestration and state management.
Handles complex multi-step authentication processes.
"""

from typing import Dict, Any, Optional
from enum import Enum
import logging
import time
from datetime import datetime

from root.authcommon.schemas import AuthFlowState, FlowStep
from root.authcommon.exceptions import InvalidFlowStateError

logger = logging.getLogger(__name__)


class AuthFlowType(Enum):
    """Types of authentication flows."""

    REGISTRATION = "registration"
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    SOCIAL_LOGIN = "social_login"
    TWO_FACTOR_SETUP = "two_factor_setup"


class AuthFlows:
    """
    Manages complex authentication flows with multiple steps.
    Handles state transitions and validation between flow steps.
    """

    def __init__(self):
        self.active_flows: Dict[str, AuthFlowState] = {}
        logger.info("AuthFlows initialized")

    def start_flow(
        self, flow_type: AuthFlowType, user_id: str, initial_data: Dict[str, Any]
    ) -> str:
        """
        Start a new authentication flow.

        Args:
            flow_type: Type of authentication flow
            user_id: User identifier
            initial_data: Initial flow data

        Returns:
            Flow ID for tracking
        """
        flow_id = f"{flow_type.value}_{user_id}_{int(time.time())}"

        flow_state = AuthFlowState(
            flow_id=flow_id,
            flow_type=flow_type.value,
            user_id=user_id,
            current_step=self._get_initial_step(flow_type),
            data=initial_data,
            created_at=datetime.utcnow(),
        )

        self.active_flows[flow_id] = flow_state

        logger.info(f"Started {flow_type.value} flow: {flow_id}")
        return flow_id

    def get_flow(self, flow_id: str) -> Optional[AuthFlowState]:
        """Get active flow by ID."""
        return self.active_flows.get(flow_id)

    def update_flow(
        self, flow_id: str, step: FlowStep, data: Dict[str, Any]
    ) -> AuthFlowState:
        """
        Update flow state with new step and data.

        Args:
            flow_id: Flow identifier
            step: New flow step
            data: Updated flow data

        Returns:
            Updated flow state
        """
        flow = self.active_flows.get(flow_id)
        if not flow:
            raise InvalidFlowStateError(f"Flow not found: {flow_id}")

        # Validate step transition
        if not self._is_valid_transition(flow.current_step, step):
            raise InvalidFlowStateError(
                f"Invalid step transition: {flow.current_step} -> {step}"
            )

        flow.current_step = step
        flow.data.update(data)
        flow.updated_at = datetime.utcnow()

        logger.info(f"Updated flow {flow_id} to step: {step}")
        return flow

    def complete_flow(self, flow_id: str) -> AuthFlowState:
        """Mark flow as completed and clean up."""
        flow = self.active_flows.get(flow_id)
        if not flow:
            raise InvalidFlowStateError(f"Flow not found: {flow_id}")

        flow.is_completed = True
        flow.completed_at = datetime.utcnow()

        # Remove from active flows
        del self.active_flows[flow_id]

        logger.info(f"Completed flow: {flow_id}")
        return flow

    def _get_initial_step(self, flow_type: AuthFlowType) -> FlowStep:
        """Get the initial step for a flow type."""
        step_mapping = {
            AuthFlowType.REGISTRATION: FlowStep.EMAIL_VERIFICATION,
            AuthFlowType.LOGIN: FlowStep.CREDENTIALS_CHECK,
            AuthFlowType.PASSWORD_RESET: FlowStep.EMAIL_VERIFICATION,
            AuthFlowType.SOCIAL_LOGIN: FlowStep.OAUTH_REDIRECT,
            AuthFlowType.TWO_FACTOR_SETUP: FlowStep.OTP_GENERATION,
        }
        return step_mapping.get(flow_type, FlowStep.CREDENTIALS_CHECK)

    def _is_valid_transition(self, current: FlowStep, next_step: FlowStep) -> bool:
        """Validate if step transition is allowed."""
        # Define valid transitions
        valid_transitions = {
            FlowStep.EMAIL_VERIFICATION: [
                FlowStep.OTP_VERIFICATION,
                FlowStep.COMPLETED,
            ],
            FlowStep.CREDENTIALS_CHECK: [FlowStep.OTP_VERIFICATION, FlowStep.COMPLETED],
            FlowStep.OTP_VERIFICATION: [FlowStep.COMPLETED, FlowStep.FAILED],
            FlowStep.OAUTH_REDIRECT: [FlowStep.OAUTH_CALLBACK, FlowStep.FAILED],
            FlowStep.OAUTH_CALLBACK: [FlowStep.COMPLETED, FlowStep.FAILED],
            FlowStep.OTP_GENERATION: [FlowStep.OTP_VERIFICATION, FlowStep.FAILED],
        }

        allowed_next_steps = valid_transitions.get(current, [])
        return next_step in allowed_next_steps
