import sys
import argparse
from src.ml.evaluate_explanations import ExplanationEvaluator

def main():
    parser = argparse.ArgumentParser(description="Evaluate SHAP Explanations on Detection Confidence & Analyst Decision-Making")
    parser.add_argument("--sample-size", type=int, default=200, help="Number of flows to evaluate")
    parser.add_argument("--interactive", action="store_true", help="Run interactive user study with analyst prompts")
    args = parser.parse_args()

    evaluator = ExplanationEvaluator()
    evaluator.run_evaluation(sample_size=args.sample_size, interactive_user_study=args.interactive)

if __name__ == "__main__":
    main()
