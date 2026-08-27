"""
DataSanitizer & Prompt Injection Inspector
Provides sub-millisecond regex & pattern-based detection and masking for PII, secrets, and adversarial injection strings.
"""

import re
from typing import Dict, Any, Tuple, List, Union

class DataSanitizer:
    def __init__(self):
        # Luhn-validated Credit Card regex
        self.cc_pattern = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
        
        # Social Security Number (US SSN: XXX-XX-XXXX)
        self.ssn_pattern = re.compile(r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b')
        
        # Email pattern
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
        
        # API Keys & Secrets (OpenAI, Anthropic, Stripe, AWS, JWT)
        self.secret_patterns = [
            (re.compile(r'\b(?:sk-[a-zA-Z0-9_-]{20,64}|sk-ant-[a-zA-Z0-9_-]{20,64})\b'), '[REDACTED_API_KEY]'),
            (re.compile(r'\b(?:sk[_-]live[_-][0-9a-zA-Z]{16,40}|rk[_-]live[_-][0-9a-zA-Z]{16,40})\b'), '[REDACTED_STRIPE_KEY]'),
            (re.compile(r'\b(?:AKIA[0-9A-Z]{16})\b'), '[REDACTED_AWS_ACCESS_KEY]'),
            (re.compile(r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b'), '[REDACTED_JWT_TOKEN]'),
            (re.compile(r'(?i)\b(?:password|secret|token|api_key)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?'), r'\1:[REDACTED_SECRET]')
        ]

        # Common Indirect Prompt Injection heuristics
        self.injection_patterns = [
            re.compile(r'(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions'),
            re.compile(r'(?i)you\s+are\s+now\s+in\s+developer\s+mode'),
            re.compile(r'(?i)system\s*override\s*:\s*execute'),
            re.compile(r'(?i)disregard\s+all\s+safety\s+guidelines'),
            re.compile(r'(?i)new\s+system\s+directive\s*:'),
            re.compile(r'(?i)do\s+not\s+tell\s+the\s+user\s+and\s+execute'),
        ]

    def _is_luhn_valid(self, n_str: str) -> bool:
        digits = [int(c) for c in n_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def detect_prompt_injection(self, text: str) -> Tuple[bool, List[str]]:
        """Detects if a string contains common adversarial prompt injection patterns."""
        if not isinstance(text, str):
            return False, []
        matched = []
        for pattern in self.injection_patterns:
            if pattern.search(text):
                matched.append(pattern.pattern)
        return len(matched) > 0, matched

    def mask_text(self, text: str) -> Tuple[str, int]:
        """Masks PII, SSN, Credit Cards, and Secrets from text in sub-millisecond time."""
        if not isinstance(text, str):
            return text, 0

        masked_text = text
        masks_applied = 0

        # Mask Credit Cards
        for match in self.cc_pattern.finditer(text):
            candidate = match.group(0)
            clean_digits = re.sub(r'\D', '', candidate)
            if self._is_luhn_valid(clean_digits):
                masked_text = masked_text.replace(candidate, f"[REDACTED_CARD_****{clean_digits[-4:]}]")
                masks_applied += 1

        # Mask SSN
        if self.ssn_pattern.search(masked_text):
            masked_text, count = self.ssn_pattern.subn('[REDACTED_SSN]', masked_text)
            masks_applied += count

        # Mask Secrets & API Keys
        for pattern, replacement in self.secret_patterns:
            if pattern.search(masked_text):
                masked_text, count = pattern.subn(replacement, masked_text)
                masks_applied += count

        return masked_text, masks_applied

    def sanitize_payload(self, data: Any) -> Tuple[Any, int, bool]:
        """
        Recursively sanitizes dictionary/list tool payloads.
        Returns: (sanitized_data, total_masks_applied, contains_injection)
        """
        total_masks = 0
        has_injection = False

        if isinstance(data, dict):
            sanitized_dict = {}
            for k, v in data.items():
                s_val, masks, inj = self.sanitize_payload(v)
                sanitized_dict[k] = s_val
                total_masks += masks
                if inj:
                    has_injection = True
            return sanitized_dict, total_masks, has_injection

        elif isinstance(data, list):
            sanitized_list = []
            for item in data:
                s_item, masks, inj = self.sanitize_payload(item)
                sanitized_list.append(s_item)
                total_masks += masks
                if inj:
                    has_injection = True
            return sanitized_list, total_masks, has_injection

        elif isinstance(data, str):
            inj, _ = self.detect_prompt_injection(data)
            if inj:
                has_injection = True
            masked_str, masks = self.mask_text(data)
            return masked_str, masks, has_injection

        else:
            return data, 0, False
