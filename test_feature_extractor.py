"""
Unit test script for feature_extractor.py
"""

import unittest
import feature_extractor


class TestFeatureExtractor(unittest.TestCase):
    def test_feature_count(self):
        self.assertEqual(len(feature_extractor.FEATURE_NAMES), 41)

    def test_features_extracted(self):
        url = "https://youtubee.com"
        feats = feature_extractor.extract_url_features(url)
        self.assertEqual(len(feats), 41)
        self.assertEqual(feats['is_brand_typo'], 1)
        self.assertEqual(feats['min_brand_edit_distance'], 1)
        self.assertEqual(feats['consecutive_char_repeat_max'], 2)

    def test_legitimate_url(self):
        url = "https://youtube.com"
        feats = feature_extractor.extract_url_features(url)
        self.assertEqual(feats['is_brand_typo'], 0)
        self.assertEqual(feats['min_brand_edit_distance'], 0)
        self.assertEqual(feats['consecutive_char_repeat_max'], 1)

    def test_impersonation_url(self):
        url = "https://microsoft-login-example.com/auth"
        feats = feature_extractor.extract_url_features(url)
        self.assertEqual(feats['brand_in_subdomain_or_path'], 1)
        self.assertEqual(feats['suspicious_hyphen_brand'], 1)
        self.assertEqual(feats['keyword_in_domain'], 1)
        self.assertGreaterEqual(feats['suspicious_keyword_count'], 1)

    def test_ip_address_url(self):
        url = "http://192.168.1.1/admin"
        feats = feature_extractor.extract_url_features(url)
        self.assertEqual(feats['has_ip_address'], 1)
        self.assertEqual(feats['https_flag'], 0)

    def test_feature_vector_format(self):
        vec = feature_extractor.extract_feature_vector("https://example.com")
        self.assertEqual(len(vec), 41)
        self.assertTrue(all(isinstance(v, (int, float)) for v in vec))


if __name__ == '__main__':
    unittest.main()
