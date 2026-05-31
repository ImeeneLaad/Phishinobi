"""
main.py
-------
Entry point for the Phishing URL Detection System — Step 1.

Usage:
    python main.py --mode train
    python main.py --mode train --data data/urls.csv --sample 50000
    python main.py --mode eval
    python main.py --mode predict --url "http://suspicious-login.tk/verify"
    python main.py --mode demo
"""

import argparse
import sys
import os


def run_train(args):
    from src.train import run_training_pipeline
    from src.evaluate import run_full_evaluation

    model, X_test, y_test = run_training_pipeline(
        data_path=args.data,
        model_path=args.model,
        sample_size=args.sample,
    )
    run_full_evaluation(model, X_test, y_test)


def run_predict(args):
    from src.predict import predict_url, print_result

    if not args.url:
        print(" Please provide a URL with --url")
        sys.exit(1)

    result = predict_url(args.url, model_path=args.model)
    print_result(result)


def run_demo(args):
    from src.predict import predict_url, print_result

    demo_urls = [
        "https://www.github.com",
        "https://google.com/search?q=weather",
        "http://paypal-secure-login.verify-account.tk/update",
        "http://192.168.0.1/admin/banking/signin.php",
        "https://accounts.google.com.phishing-test.xyz/signin",
        "https://amazon.com/dp/B09XYZ123/ref=nav",
        "http://amaz0n-account-verify.com/login?redirect=ebay",
        "https://secure.wellsfargo.com/auth/login",
    ]

    print("\n  PHISHING DETECTOR — DEMO MODE\n")
    for url in demo_urls:
        try:
            result = predict_url(url, model_path=args.model)
            print_result(result)
        except Exception as e:
            print(f"Error on {url}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="  Phishing URL Detection System — Step 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --mode train
  python main.py --mode train --sample 50000
  python main.py --mode predict --url "http://paypal-login.tk/verify"
  python main.py --mode demo
        """
    )

    parser.add_argument(
        "--mode", choices=["train", "predict", "demo"],
        required=True, help="What to run"
    )
    parser.add_argument("--url",    default=None,                    help="URL to analyze (predict mode)")
    parser.add_argument("--data",   default="data/urls.csv",         help="Path to dataset CSV")
    parser.add_argument("--model",  default="models/phishing_model.pkl", help="Path to model file")
    parser.add_argument("--sample", default=None, type=int,          help="Limit training rows (for quick test)")

    args = parser.parse_args()

    if args.mode == "train":
        run_train(args)
    elif args.mode == "predict":
        run_predict(args)
    elif args.mode == "demo":
        run_demo(args)


if __name__ == "__main__":
    main()
