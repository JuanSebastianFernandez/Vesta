import unittest
from app.services.feature_extractor import extract_feature_vector, clean_source_code, _shannon_entropy

class TestFeatureExtractor(unittest.TestCase):

    def test_clean_source_code(self):
        """Verifica que se eliminen comentarios y strings."""
        code = "import os # Este es un comentario\n/* Bloque \n comentario */ class Test:"
        cleaned = clean_source_code(code)
        self.assertNotIn("#", cleaned)
        self.assertNotIn("/*", cleaned)
        self.assertIn("import", cleaned)
        self.assertIn("class", cleaned)

    def test_entropy_logic(self):
        """La entropía de un string repetitivo debe ser baja."""
        self.assertEqual(_shannon_entropy(""), 0.0)
        # Un string con un solo caracter repetido tiene entropía 0
        self.assertEqual(_shannon_entropy("aaaaa"), 0.0)
        # Un string variado debe tener entropía mayor a 0
        self.assertGreater(_shannon_entropy("abcde123"), 1.0)

    def test_keyword_counting(self):
        """Verifica que cuente keywords exactas (case insensitive)."""
        code = "public static void main(String[] args) { void(); }"
        # Debería encontrar 'void' 2 veces y 'static' 1 vez
        vector = extract_feature_vector(code)
        self.assertEqual(vector["ImageBase"], 2.0)  # ImageBase mapea a 'void'
        self.assertEqual(vector["LoaderFlags"], 1.0) # LoaderFlags mapea a 'static'

    def test_edge_cases(self):
        """Prueba con entradas nulas o vacías."""
        # Caso: Input no es string
        vector_invalid = extract_feature_vector(None)
        self.assertEqual(vector_invalid["Name"], 0.0)
        
        # Caso: Código vacío
        vector_empty = extract_feature_vector("   ", file_name="test.java")
        self.assertEqual(vector_empty["Name"], 9.0) # len("test.java")
        self.assertEqual(vector_empty["SectionsMeanEntropy"], 0.0)

    def test_vector_structure(self):
        """Asegura que siempre devuelva las 12 características."""
        vector = extract_feature_vector("import math")
        self.assertEqual(len(vector), 12)
        expected_keys = [
            "SectionsMeanEntropy", "ResourcesMaxEntropy", "SectionsMeanVirtualsize",
            "SizeOfStackCommit", "MajorOSVersion", "ResourcesMeanEntropy",
            "Name", "SectionsMinRawsize", "MinorSubsystemVersion",
            "LoaderFlags", "ImportsNbDLL", "ImageBase"
        ]
        self.assertListEqual(list(vector.keys()), expected_keys)

if __name__ == "__main__":
    unittest.main()