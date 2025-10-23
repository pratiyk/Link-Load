"""Enhanced MITRE ATT&CK mapping service with multi-algorithm ensemble."""
from __future__ import annotations

from typing import List, Dict, Any, Optional
import logging
import asyncio
import re

import numpy as np

try:  # Optional NLP dependency
    import spacy  # type: ignore
except ImportError:  # pragma: no cover
    spacy = None  # type: ignore

try:  # Optional similarity dependency
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore
except ImportError:  # pragma: no cover
    cosine_similarity = None  # type: ignore

try:  # Optional transformer dependency
    from transformers import AutoTokenizer, AutoModel  # type: ignore
except ImportError:  # pragma: no cover
    AutoTokenizer = None  # type: ignore
    AutoModel = None  # type: ignore

try:  # Optional torch dependency
    import torch  # type: ignore
except ImportError:  # pragma: no cover
    torch = None  # type: ignore

from app.models.threat_intel_models import MITRETechnique, MITRETactic
from app.models.mitre_models import CAPEC
from app.core.config import settings
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

class MITREMapper:
    """
    Enhanced MITRE ATT&CK mapping service using multi-algorithm ensemble
    for accurate technique and sub-technique mapping.
    """
    
    def __init__(self, db: Session):
        """Initialize the MITRE mapper with required models and databases."""
        self.db = db
        self.keyword_library = {
            "sql injection",
            "buffer overflow",
            "remote code execution",
            "cross-site scripting",
            "command injection",
            "privilege escalation",
            "lateral movement",
        }

        # Initialize NLP models only if dependencies are available
        self.nlp = None
        self.spacy_enabled = False
        if spacy is not None:
            for model_name in ("en_core_web_lg", "en_core_web_sm"):
                try:
                    self.nlp = spacy.load(model_name)  # type: ignore[attr-defined]
                    self.spacy_enabled = True
                    break
                except Exception:
                    continue

        self.tokenizer = None
        self.model = None
        self.device = "cpu"
        self.semantic_enabled = False
        if all([AutoTokenizer, AutoModel, torch, cosine_similarity]):
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    "microsoft/mpnet-base",
                    local_files_only=True,
                )
                self.model = AutoModel.from_pretrained(
                    "microsoft/mpnet-base",
                    local_files_only=True,
                )
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.model.to(self.device)  # type: ignore[operator]
                self.semantic_enabled = True
            except Exception:
                self.tokenizer = None
                self.model = None
                self.semantic_enabled = False
        
        # Cache for MITRE data
        self.techniques_cache: Dict[str, MITRETechnique] = {}
        self.tactics_cache: Dict[str, MITRETactic] = {}
        self.capec_cache: Dict[str, CAPEC] = {}
        
        # Mapping confidence thresholds
        self.SEMANTIC_THRESHOLD = 0.75
        self.SYNTACTIC_THRESHOLD = 0.60
        self.RULE_THRESHOLD = 0.50
        
        self._load_caches()

    def _fetch_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Return a technique from cache, refreshing from the DB if needed."""
        cache_key = str(technique_id)
        technique = self.techniques_cache.get(cache_key)
        if technique is not None:
            return technique

        # Ensure the session sees the latest committed rows
        try:
            self.db.expire_all()
        except Exception:  # pragma: no cover - defensive safeguard
            pass

        technique = self.db.get(MITRETechnique, technique_id)
        if technique is not None:
            self.techniques_cache[cache_key] = technique
        return technique

    def _load_caches(self):
        """Load MITRE data into memory caches for faster access."""
        try:
            self.db.expire_all()
        except Exception:  # pragma: no cover - defensive safeguard
            pass

        self.techniques_cache = {
            str(tech.technique_id): tech for tech in 
            self.db.query(MITRETechnique).all()
        }
        self.tactics_cache = {
            str(tactic.tactic_id): tactic for tactic in 
            self.db.query(MITRETactic).all()
        }
        self.capec_cache = {
            str(pattern.pattern_id): pattern for pattern in 
            self.db.query(CAPEC).all()
        }

    async def map_vulnerability(
        self, 
        description: str, 
        cve_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Map vulnerability to MITRE ATT&CK techniques using ensemble approach.
        """
        if description is None:
            raise ValueError("Description is required for MITRE mapping")

        clean_text = description.strip()
        if not clean_text:
            empty_matches: List[Dict[str, Any]] = []
            return {
                "techniques": empty_matches,
                "ttps": [],
                "capec_patterns": [],
                "confidence_explanation": self._generate_explanation(empty_matches),
            }

        # Ensure caches stay in sync with the latest database state
        self._load_caches()

        results = await asyncio.gather(
            self._semantic_mapping(clean_text),
            self._syntactic_mapping(clean_text),
            self._rule_based_mapping(clean_text, cve_id),
        )
        
        # Combine results using weighted ensemble
        semantic_matches, syntactic_matches, rule_matches = results
        
        combined_matches = self._ensemble_combine(
            semantic_matches,
            syntactic_matches,
            rule_matches
        )
        
        # Get related TTPs and CAPEC patterns
        ttps = await self._get_related_ttps(combined_matches)
        capec_patterns = await self._get_capec_correlations(combined_matches)
        
        return {
            "techniques": combined_matches,
            "ttps": ttps,
            "capec_patterns": capec_patterns,
            "confidence_explanation": self._generate_explanation(combined_matches)
        }

    async def _semantic_mapping(self, text: str) -> List[Dict[str, Any]]:
        """Semantic similarity mapping using transformer embeddings."""
        if not (
            self.semantic_enabled
            and self.tokenizer is not None
            and self.model is not None
            and torch is not None
            and cosine_similarity is not None
        ):
            return self._basic_keyword_match(text, method="semantic")

        # Get text embedding using transformer model
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self.device)
        with torch.no_grad():  # type: ignore[attr-defined]
            outputs = self.model(**inputs)
        text_embedding = outputs.last_hidden_state.mean(dim=1)

        matches: List[Dict[str, Any]] = []
        for tech_id, technique in self.techniques_cache.items():
            technique_text = self._normalize_description(technique.description)
            if not technique_text:
                continue

            tech_inputs = self.tokenizer(
                technique_text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            ).to(self.device)

            with torch.no_grad():  # type: ignore[attr-defined]
                tech_outputs = self.model(**tech_inputs)
            tech_embedding = tech_outputs.last_hidden_state.mean(dim=1)

            similarity = float(
                cosine_similarity(  # type: ignore[operator]
                    text_embedding.cpu().numpy(),
                    tech_embedding.cpu().numpy(),
                )[0][0]
            )

            if similarity >= self.SEMANTIC_THRESHOLD:
                matches.append(
                    {
                        "technique_id": tech_id,
                        "confidence": similarity,
                        "method": "semantic",
                    }
                )

        return matches

    async def _syntactic_mapping(self, text: str) -> List[Dict[str, Any]]:
        """Pattern and keyword-based syntactic mapping."""
        if not text:
            return []

        if not self.spacy_enabled or self.nlp is None:
            return self._basic_keyword_match(text, "syntactic")

        assert self.nlp is not None  # For type checkers
        doc = self.nlp(text.lower())
        matches = []
        
        for tech_id, technique in self.techniques_cache.items():
            description_text = self._normalize_description(technique.description).lower()

            # Create pattern matchers
            tech_doc = self.nlp(description_text)
            
            # Check for shared noun phrases and verbs
            shared_phrases = len(set(
                chunk.text for chunk in doc.noun_chunks
            ).intersection(
                chunk.text for chunk in tech_doc.noun_chunks
            ))
            
            shared_verbs = len(set(
                token.lemma_ for token in doc if token.pos_ == "VERB"
            ).intersection(
                token.lemma_ for token in tech_doc if token.pos_ == "VERB"
            ))
            
            # Calculate syntactic similarity score
            similarity = (shared_phrases + shared_verbs) / (
                len(list(doc.noun_chunks)) + 
                len([t for t in doc if t.pos_ == "VERB"])
            )
            
            if similarity >= self.SYNTACTIC_THRESHOLD:
                matches.append({
                    "technique_id": tech_id,
                    "confidence": similarity,
                    "method": "syntactic"
                })
        
        return matches

    async def _rule_based_mapping(
        self, 
        text: str, 
        cve_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Rule-based mapping using predefined patterns and CVE correlations."""
        matches = []
        
        # Check for direct technique mentions
        for tech_id, technique in self.techniques_cache.items():
            if technique.name.lower() in text.lower():
                matches.append({
                    "technique_id": tech_id,
                    "confidence": 0.9,
                    "method": "rule"
                })
                
        # Check for attack pattern indicators
        attack_patterns = [
            (r"buffer\s+overflow", "T1588.005"),
            (r"sql\s+injection", "T1190"),
            (r"cross-site\s+scripting", "T1189"),
            (r"command\s+injection", "T1203"),
            # Add more patterns
        ]
        
        for pattern, tech_id in attack_patterns:
            if re.search(pattern, text.lower()):
                if self._fetch_technique(tech_id) is None:
                    continue
                matches.append({
                    "technique_id": tech_id,
                    "confidence": 0.85,
                    "method": "rule"
                })
                
        # CVE correlation if available
        if cve_id:
            cve_matches = await self._get_cve_technique_correlations(cve_id)
            matches.extend(cve_matches)
            
        return matches

    def _basic_keyword_match(self, text: str, method: str) -> List[Dict[str, Any]]:
        """Simple keyword-based fallback matching when NLP dependencies are unavailable."""
        if not text:
            return []

        lower_text = text.lower()
        matches: List[Dict[str, Any]] = []

        for tech_id, technique in self.techniques_cache.items():
            name = (technique.name or "").lower()
            desc = self._normalize_description(technique.description).lower()

            score = 0.0
            tokens = [token for token in re.split(r"[^a-z0-9]+", name) if token]
            if tokens:
                token_hits = sum(1 for token in tokens if token in lower_text)
                if token_hits:
                    score += 0.2 + 0.1 * token_hits
                    if token_hits == len(tokens):
                        score += 0.2

            for phrase in self.keyword_library:
                if phrase in lower_text and (phrase in desc or phrase in name):
                    score += 0.3

            if score > 0:
                matches.append(
                    {
                        "technique_id": tech_id,
                        "confidence": min(1.0, max(self.RULE_THRESHOLD, score)),
                        "method": method,
                    }
                )

        return matches

    def _ensemble_combine(
        self,
        semantic_matches: List[Dict[str, Any]],
        syntactic_matches: List[Dict[str, Any]],
        rule_matches: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Combine results from different matching methods with weighted voting."""
        weights = {
            "semantic": 0.4,
            "syntactic": 0.3,
            "rule": 0.3
        }

        combined_scores: Dict[str, Dict[str, Any]] = {}

        # Combine all matches
        all_matches = semantic_matches + syntactic_matches + rule_matches

        for match in all_matches:
            tech_id = match["technique_id"]
            technique = self._fetch_technique(tech_id)
            if technique is None:
                logger.debug("Skipping technique %s - not found in cache", tech_id)
                continue

            entry = combined_scores.setdefault(
                tech_id,
                {
                    "technique_id": tech_id,
                    "technique": technique,
                    "confidence": 0.0,
                    "methods": set(),
                    "_weight_sum": 0.0,
                },
            )

            weight = weights.get(match["method"], 0.3)
            entry["confidence"] += match["confidence"] * weight
            entry["_weight_sum"] += weight
            entry["methods"].add(match["method"])

        # Normalize and filter results
        results: List[Dict[str, Any]] = []
        for tech_id, score in combined_scores.items():
            weight_sum = score.pop("_weight_sum", 0.0)
            if weight_sum > 0:
                score["confidence"] = min(score["confidence"] / weight_sum, 1.0)
            score["methods"] = list(score["methods"])

            if score["confidence"] >= self.RULE_THRESHOLD:
                results.append(score)

        return sorted(results, key=lambda x: x["confidence"], reverse=True)

    async def _get_related_ttps(
        self,
        techniques: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Get related TTPs for matched techniques."""
        ttps = []
        
        for tech in techniques:
            technique = self._fetch_technique(tech["technique_id"])
            if technique is None:
                continue
            description_text = self._normalize_description(technique.description)

            # Get related tactics
            for tactic in technique.tactics:
                ttp = {
                    "tactic": tactic.name,
                    "technique": technique.name,
                    "procedure": self._extract_procedures(description_text),
                    "confidence": tech["confidence"]
                }
                ttps.append(ttp)
                
        return ttps

    async def _get_capec_correlations(
        self,
        techniques: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Get related CAPEC patterns for matched techniques."""
        patterns = []
        
        for tech in techniques:
            technique = self._fetch_technique(tech["technique_id"])
            if technique is None:
                continue
            
            # Find related CAPEC patterns
            related_patterns = self.db.query(CAPEC).filter(
                CAPEC.mitre_technique_ids.contains([technique.technique_id])
            ).all()
            
            for pattern in related_patterns:
                patterns.append({
                    "pattern_id": pattern.pattern_id,
                    "name": pattern.name,
                    "description": pattern.description,
                    "likelihood": pattern.typical_likelihood or pattern.likelihood,
                    "related_technique": technique.name,
                    "confidence": tech["confidence"] * 0.9  # Slight reduction
                })
                
        return patterns

    def _generate_explanation(
        self,
        matches: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate explainable AI output for mapping decisions."""
        explanation = {
            "overall_confidence": 0,
            "matching_methods": {},
            "decision_factors": []
        }
        
        if not matches:
            return explanation
            
        # Calculate overall confidence
        explanation["overall_confidence"] = sum(
            m["confidence"] for m in matches
        ) / len(matches)
        
        # Analyze matching methods used
        method_counts = {}
        for match in matches:
            for method in match["methods"]:
                method_counts[method] = method_counts.get(method, 0) + 1
                
        explanation["matching_methods"] = {
            method: {
                "count": count,
                "percentage": (count / len(matches)) * 100
            }
            for method, count in method_counts.items()
        }
        
        # Add decision factors
        for match in matches:
            technique = self._fetch_technique(match["technique_id"])
            if technique is None:
                continue
            factors = {
                "technique": technique.name,
                "confidence": match["confidence"],
                "methods_used": match["methods"],
                "key_factors": [
                    f"Matched by {len(match['methods'])} different methods",
                    f"Highest confidence: {max(match['confidence'], 0.8):.2f}"
                ]
            }
            explanation["decision_factors"].append(factors)
            
        return explanation

    def _extract_procedures(self, description: str) -> List[str]:
        """Extract potential procedures from technique description."""
        if not description:
            return []

        if not self.spacy_enabled or self.nlp is None:
            sentences = re.split(r"[.!?]\s+", description)
            return [
                sentence.strip()
                for sentence in sentences
                if any(keyword in sentence.lower() for keyword in self.keyword_library)
            ]

        assert self.nlp is not None  # For type checkers
        doc = self.nlp(description)
        procedures = []
        
        # Look for action phrases
        for sent in doc.sents:
            if any(token.pos_ == "VERB" for token in sent):
                # Extract verb phrases
                for token in sent:
                    if token.pos_ == "VERB":
                        # Get the verb phrase
                        phrase = " ".join([
                            t.text for t in token.subtree
                            if not t.dep_ == "punct"
                        ])
                        procedures.append(phrase.strip())
                        
        return list(set(procedures))  # Remove duplicates

    @staticmethod
    def _normalize_description(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    async def _get_cve_technique_correlations(
        self,
        cve_id: str
    ) -> List[Dict[str, Any]]:
        """Get MITRE technique correlations for a CVE."""
        # This would typically involve an external API call or database lookup
        # For now, return an empty list as this requires additional data sources
        return []