"""
Enhanced MITRE ATT&CK mapping service with multi-algorithm ensemble.
"""
from typing import List, Dict, Any, Optional, Tuple
import spacy
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from transformers import AutoTokenizer, AutoModel
import torch
from app.models.threat_intel_models import MITRETechnique, MITRETactic, CAPEC
from app.core.config import settings
import logging
from sqlalchemy.orm import Session
import asyncio
import re

logger = logging.getLogger(__name__)

class MITREMapper:
    """
    Enhanced MITRE ATT&CK mapping service using multi-algorithm ensemble
    for accurate technique and sub-technique mapping.
    """
    
    def __init__(self, db: Session):
        """Initialize the MITRE mapper with required models and databases."""
        self.db = db
        # Initialize NLP models
        self.nlp = spacy.load("en_core_web_lg")
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/mpnet-base")
        self.model = AutoModel.from_pretrained("microsoft/mpnet-base")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        
        # Cache for MITRE data
        self.techniques_cache = {}
        self.tactics_cache = {}
        self.capec_cache = {}
        
        # Mapping confidence thresholds
        self.SEMANTIC_THRESHOLD = 0.75
        self.SYNTACTIC_THRESHOLD = 0.60
        self.RULE_THRESHOLD = 0.50
        
        self._load_caches()

    def _load_caches(self):
        """Load MITRE data into memory caches for faster access."""
        self.techniques_cache = {
            tech.technique_id: tech for tech in 
            self.db.query(MITRETechnique).all()
        }
        self.tactics_cache = {
            tactic.tactic_id: tactic for tactic in 
            self.db.query(MITRETactic).all()
        }
        self.capec_cache = {
            pattern.pattern_id: pattern for pattern in 
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
        results = await asyncio.gather(
            self._semantic_mapping(description),
            self._syntactic_mapping(description),
            self._rule_based_mapping(description, cve_id)
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
        # Get text embedding
        inputs = self.tokenizer(text, return_tensors="pt", 
                              truncation=True, max_length=512).to(self.device)
        with torch.no_grad():
            outputs = self.model(**inputs)
        text_embedding = outputs.last_hidden_state.mean(dim=1)
        
        matches = []
        for tech_id, technique in self.techniques_cache.items():
            # Get technique embedding
            tech_inputs = self.tokenizer(
                technique.description,
                return_tensors="pt",
                truncation=True,
                max_length=512
            ).to(self.device)
            
            with torch.no_grad():
                tech_outputs = self.model(**tech_inputs)
            tech_embedding = tech_outputs.last_hidden_state.mean(dim=1)
            
            # Calculate similarity
            similarity = float(cosine_similarity(
                text_embedding.cpu().numpy(),
                tech_embedding.cpu().numpy()
            )[0][0])
            
            if similarity >= self.SEMANTIC_THRESHOLD:
                matches.append({
                    "technique_id": tech_id,
                    "confidence": similarity,
                    "method": "semantic"
                })
                
        return matches

    async def _syntactic_mapping(self, text: str) -> List[Dict[str, Any]]:
        """Pattern and keyword-based syntactic mapping."""
        doc = self.nlp(text.lower())
        matches = []
        
        for tech_id, technique in self.techniques_cache.items():
            # Create pattern matchers
            tech_doc = self.nlp(technique.description.lower())
            
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
        
        combined_scores = {}
        
        # Combine all matches
        all_matches = semantic_matches + syntactic_matches + rule_matches
        
        for match in all_matches:
            tech_id = match["technique_id"]
            if tech_id not in combined_scores:
                combined_scores[tech_id] = {
                    "technique_id": tech_id,
                    "technique": self.techniques_cache[tech_id],
                    "confidence": 0,
                    "methods": []
                }
                
            # Add weighted confidence
            weight = weights[match["method"]]
            combined_scores[tech_id]["confidence"] += match["confidence"] * weight
            combined_scores[tech_id]["methods"].append(match["method"])
            
        # Normalize and filter results
        results = []
        for tech_id, score in combined_scores.items():
            # Normalize by number of methods that detected it
            score["confidence"] = min(
                score["confidence"] / len(score["methods"]),
                1.0
            )
            
            if score["confidence"] >= self.RULE_THRESHOLD:
                results.append(score)
                
        return sorted(
            results,
            key=lambda x: x["confidence"],
            reverse=True
        )

    async def _get_related_ttps(
        self,
        techniques: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Get related TTPs for matched techniques."""
        ttps = []
        
        for tech in techniques:
            technique = self.techniques_cache[tech["technique_id"]]
            
            # Get related tactics
            for tactic in technique.tactics:
                ttp = {
                    "tactic": tactic.name,
                    "technique": technique.name,
                    "procedure": self._extract_procedures(technique.description),
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
            technique = self.techniques_cache[tech["technique_id"]]
            
            # Find related CAPEC patterns
            related_patterns = self.db.query(CAPEC).filter(
                CAPEC.mitre_technique_ids.contains([technique.technique_id])
            ).all()
            
            for pattern in related_patterns:
                patterns.append({
                    "pattern_id": pattern.pattern_id,
                    "name": pattern.name,
                    "description": pattern.description,
                    "likelihood": pattern.typical_likelihood,
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
            technique = self.techniques_cache[match["technique_id"]]
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

    async def _get_cve_technique_correlations(
        self,
        cve_id: str
    ) -> List[Dict[str, Any]]:
        """Get MITRE technique correlations for a CVE."""
        # This would typically involve an external API call or database lookup
        # For now, return an empty list as this requires additional data sources
        return []