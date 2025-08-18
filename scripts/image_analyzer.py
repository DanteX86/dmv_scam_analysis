#!/usr/bin/env python3
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import cv2
import pytesseract
from PIL import Image


class ImageAnalyzer:
    def __init__(self, image_dir: str) -> None:
        self.image_dir: str = image_dir
        self.analysis_results: Dict[str, Any] = {}

    def analyze_image(self, image_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a single image and extract relevant information."""
        try:
            # Read image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError(f"Could not read image: {image_path}")

            # Basic image properties
            height, width = img.shape[:2]

            # Extract text using OCR
            pil_image = Image.open(image_path)
            extracted_text = pytesseract.image_to_string(pil_image)

            # Analyze image quality
            blur_score = cv2.Laplacian(
                cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), cv2.CV_64F
            ).var()

            return {
                "file_name": os.path.basename(image_path),
                "dimensions": f"{width}x{height}",
                "size_kb": os.path.getsize(image_path) / 1024,
                "blur_score": blur_score,  # Higher values indicate sharper images
                "extracted_text": extracted_text.strip(),
                "analysis_time": datetime.now().isoformat(),
            }

        except Exception as e:
            print(f"Error analyzing {image_path}: {str(e)}")
            return None

    def analyze_evidence_batch(
        self, subdirectory: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Analyze all images in a specified subdirectory of the evidence folder."""
        target_dir = (
            os.path.join(self.image_dir, subdirectory)
            if subdirectory
            else self.image_dir
        )

        if not os.path.exists(target_dir):
            print(f"Directory not found: {target_dir}")
            return []

        results: List[Dict[str, Any]] = []
        for filename in os.listdir(target_dir):
            if filename.lower().endswith((".png", ".jpg", ".jpeg", ".tiff", ".bmp")):
                image_path = os.path.join(target_dir, filename)
                result = self.analyze_image(image_path)
                if result:
                    results.append(result)

        return results

    def generate_report(
        self, results: List[Dict[str, Any]], report_type: str = "full"
    ) -> str:
        """Generate a formatted report of the analysis results."""
        if not results:
            return "No analysis results available."

        report = "=== Image Analysis Report ===\n"
        report += f"Analysis Time: {datetime.now().isoformat()}\n"
        report += f"Number of Images Analyzed: {len(results)}\n\n"

        for result in results:
            report += f"File: {result['file_name']}\n"
            report += f"Dimensions: {result['dimensions']}\n"
            report += f"Size: {result['size_kb']:.2f} KB\n"
            report += f"Image Quality (Blur Score): {result['blur_score']:.2f}\n"

            if report_type == "full":
                report += "Extracted Text:\n"
                report += "-" * 40 + "\n"
                report += result["extracted_text"] + "\n"
                report += "-" * 40 + "\n"

            report += "\n"

        return report


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python image_analyzer.py <evidence_dir>")
        sys.exit(1)

    evidence_dir = sys.argv[1]
    analyzer = ImageAnalyzer(evidence_dir)

    # Analyze envelope images
    print("Analyzing envelope images...")
    envelope_results = analyzer.analyze_evidence_batch("envelope")
    if envelope_results:
        print(analyzer.generate_report(envelope_results))

    # Analyze letter images
    print("\nAnalyzing letter images...")
    letter_results = analyzer.analyze_evidence_batch("letter")
    if letter_results:
        print(analyzer.generate_report(letter_results))


if __name__ == "__main__":
    main()
