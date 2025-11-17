#!/usr/bin/env python3
"""
Dataset Downloader for Phishing Detection System

This script downloads sample email datasets for testing the phishing detection system.
It provides options to download legitimate emails from the Enron dataset and
phishing emails from public repositories.
"""

import os
import argparse
import urllib.request
import zipfile
import tarfile
import shutil
from pathlib import Path
from tqdm import tqdm
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Dataset URLs
DATASETS = {
    "enron": {
        "url": "https://www.cs.cmu.edu/~enron/enron_mail_20110402.tgz",
        "type": "legitimate",
        "description": "Enron Email Dataset (subset)"
    },
    "phishing": {
        "url": "https://monkey.org/~jose/phishing/phishing3.mbox",
        "type": "phishing",
        "description": "Phishing Email Corpus"
    }
}


class DownloadProgressBar(tqdm):
    """Progress bar for downloads."""
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


def download_file(url, output_path):
    """
    Download a file with a progress bar.
    
    Args:
        url: URL to download
        output_path: Path to save the downloaded file
    """
    with DownloadProgressBar(unit='B', unit_scale=True, miniters=1, desc=url.split('/')[-1]) as t:
        urllib.request.urlretrieve(url, filename=output_path, reporthook=t.update_to)


def extract_archive(archive_path, extract_dir, dataset_type):
    """
    Extract an archive file.
    
    Args:
        archive_path: Path to the archive file
        extract_dir: Directory to extract to
        dataset_type: Type of dataset (for logging)
    """
    logger.info(f"Extracting {dataset_type} dataset...")
    
    if archive_path.endswith('.tgz') or archive_path.endswith('.tar.gz'):
        with tarfile.open(archive_path) as tar:
            # Extract only a subset for the Enron dataset (it's very large)
            if 'enron' in archive_path:
                members = []
                for i, member in enumerate(tar.getmembers()):
                    if i > 1000:  # Limit to 1000 files for sample purposes
                        break
                    if member.isreg():  # Regular files only
                        members.append(member)
                for member in tqdm(members, desc="Extracting files"):
                    try:
                        tar.extract(member, path=extract_dir)
                    except PermissionError:
                        logger.warning(f"Permission denied extracting {member.name}, skipping.")
            else:
                tar.extractall(path=extract_dir)
    elif archive_path.endswith('.zip'):
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
    elif archive_path.endswith('.mbox'):
        # For .mbox files, we'll convert them to individual .eml files
        convert_mbox_to_eml(archive_path, os.path.join(extract_dir, 'phishing'))
    else:
        logger.error(f"Unsupported archive format: {archive_path}")


def convert_mbox_to_eml(mbox_path, output_dir):
    """
    Convert an mbox file to individual .eml files.
    
    Args:
        mbox_path: Path to the mbox file
        output_dir: Directory to save the .eml files
    """
    try:
        import mailbox
    except ImportError:
        logger.error("mailbox module not available. Cannot convert mbox to eml.")
        return
    
    os.makedirs(output_dir, exist_ok=True)
    
    logger.info(f"Converting mbox to individual .eml files in {output_dir}...")
    mbox = mailbox.mbox(mbox_path)
    
    for i, message in enumerate(tqdm(mbox, desc="Converting emails")):
        if i >= 100:  # Limit to 100 phishing emails for sample purposes
            break
        
        eml_path = os.path.join(output_dir, f"phishing_sample_{i+1}.eml")
        with open(eml_path, 'wb') as f:
            f.write(message.as_bytes())


def download_dataset(dataset_name, output_dir, force=False):
    """
    Download and extract a dataset.
    
    Args:
        dataset_name: Name of the dataset to download
        output_dir: Directory to save the dataset
        force: Whether to force download even if files exist
    """
    if dataset_name not in DATASETS:
        logger.error(f"Unknown dataset: {dataset_name}")
        return
    
    dataset = DATASETS[dataset_name]
    dataset_type = dataset["type"]
    url = dataset["url"]
    description = dataset["description"]
    
    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    type_dir = os.path.join(output_dir, dataset_type)
    os.makedirs(type_dir, exist_ok=True)
    
    # Download file
    filename = url.split('/')[-1]
    download_path = os.path.join(output_dir, filename)
    
    if os.path.exists(download_path) and not force:
        logger.info(f"{description} already downloaded. Use --force to re-download.")
    else:
        logger.info(f"Downloading {description}...")
        download_file(url, download_path)
    
    # Extract archive
    extract_archive(download_path, type_dir, dataset_type)
    
    logger.info(f"{description} downloaded and extracted successfully.")


def main():
    """
    Main function to parse arguments and download datasets.
    """
    parser = argparse.ArgumentParser(
        description="Download email datasets for phishing detection testing"
    )
    
    parser.add_argument(
        "--dataset", "-d",
        choices=["enron", "phishing", "all"],
        default="all",
        help="Which dataset to download"
    )
    
    parser.add_argument(
        "--output", "-o",
        default="./data",
        help="Output directory for datasets"
    )
    
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force download even if files exist"
    )
    
    args = parser.parse_args()
    
    # Resolve output directory path
    output_dir = os.path.abspath(args.output)
    
    # Download selected datasets
    if args.dataset in ["enron", "all"]:
        download_dataset("enron", output_dir, args.force)
    
    if args.dataset in ["phishing", "all"]:
        download_dataset("phishing", output_dir, args.force)
    
    logger.info(f"All requested datasets downloaded to {output_dir}")
    logger.info("You can now use these datasets with the phishing detection system.")


if __name__ == "__main__":
    main()