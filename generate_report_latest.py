# Copyright (C) Samuel Henrique <samueloph@debian.org>
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3. This program is distributed in the hope that
# it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details. You should have received a
# copy of the GNU Affero General Public License along with this program. If
# not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0

#!/usr/bin/python3

import json
import subprocess
import datetime
import os
import argparse
import logging
import docker
from docker import DockerClient
from docker.models.containers import Container
import colorlog
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import threading

# Set up colored logging
handler: colorlog.StreamHandler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
)

logger: logging.Logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Initialize thread-safe error tracking
error_lock = threading.Lock()
errors: Dict[str, List[str]] = {
    "pull": [],
    "create_container": [],
    "start_container": [],
    "update": [],
    "scan": [],
    "stop_container": [],
    "remove_container": [],
    "other": [],
}

def add_error(category: str, image_name: str) -> None:
    """
    Add an error to the thread-safe error tracking dictionary.

    :param category: The category of the error
    :param image_name: The name of the image that encountered the error
    """
    with error_lock:
        if category not in errors:
            errors[category] = []
        errors[category].append(image_name)

def get_errors() -> Dict[str, List[str]]:
    """
    Get a copy of the current errors dictionary.

    :return: A copy of the errors dictionary
    """
    with error_lock:
        return errors.copy()

def update_and_create_new_image(docker_client: DockerClient, image_name: str):
    # Pull image.
    try:
        logger.debug(f"[{image_name}] - Pulling image")
        docker_client.images.pull(image_name)
    except Exception as e:
        logger.error(
            f"[{image_name}] - Error pulling image: {str(e)}"
        )
        add_error("pull", image_name)
        raise e

    # Create container.
    try:
        container:Container = docker_client.containers.create(
            image=image_name,
            command="/bin/sh",
            detach=True,
            tty=True,
            stdin_open=True,
            name=f"{image_name.replace(':', '_').replace('/', '_')}-{datetime.datetime.now().strftime('%Y_%m_%d')}"
        ) # type: ignore
        logger.debug(f"Container created successfully: {container.id}")
    except Exception as e:
        logger.error(
            f"[{image_name}] - Error creating container: {str(e)}"
        )
        add_error("create_container", image_name)
        remove_image(docker_client, image_name)
        raise e

    # Start container.
    try:
        logger.debug(f"[{image_name}] - Starting container")
        container.start()
        logger.debug(f"[{image_name}] - Container {container.id} is now running")
    except Exception as e:
        logger.error(
            f"[{image_name}] - Error starting container: {str(e)}"
        )
        add_error("start_container", image_name)
        container.remove()
        remove_image(docker_client, image_name)
        raise e

    shell_update_command = """if export DEBIAN_FRONTEND=noninteractive && apt update && apt upgrade -y; then
    echo 'APT UPDATE SUCCESS';
    elif apk update && apk upgrade --available; then
    echo 'APK UPDATE SUCCESS';
    elif dnf update -y; then
    echo 'DNF update SUCESS';
    fi
    """
    update_command: List[str] = [
        "/usr/bin/timeout",
        "15m",
        "/bin/sh",
        "-c",
        shell_update_command,
    ]

    # Update container.
    logger.info(f"[{image_name}] - Running update command in container: {container.id}")
    try:
        exit_code, output = container.exec_run(update_command, user="root")
        if exit_code != 0:
            logger.error(
                f"[{image_name}] - Update command exited with non-zero status: {exit_code} for container {container.id}, output: {output}"
            )
            add_error("update", image_name)
        logger.info(
            f"[{image_name}] - Update command output for container {container.id}: {output.decode('utf-8', errors='replace')}"
        )
    except Exception as e:
        logger.error(
            f"[{image_name}] - Error executing command in container {container.id}: {str(e)}"
        )
        add_error("update", image_name)

    logger.debug(f"[{image_name}] - Stopping container: {container.id}")
    try:
        container.stop()
    except Exception as e:
        logger.error(
            f"[{image_name}] - Error stopping container {container}: {str(e)}"
        )
        add_error("stop_container", image_name)

    new_image_name: str = f"{image_name}-updated"
    logger.debug(
        f"[{image_name}] - Creating new image: {new_image_name} from container {container.id}"
    )
    container.commit(repository=new_image_name)
    try:
        container.remove()
    except Exception as e:
        logger.error(
            f"[{image_name}] - Error removing container {container}: {str(e)}"
        )
        add_error("remove_container", image_name)

# Run grype scanner against an image, returns the json output from grype.
def scan_image_with_grype(image: str) -> Dict[str, Any]:
    logger.debug(f"[{image}] - Starting Grype scan")
    result: subprocess.CompletedProcess = subprocess.run(
        ["grype", image, "-o", "json"], capture_output=True, text=True, check=True
    )
    logger.info(f"[{image}] - Completed Grype scan")
    grype_result = json.loads(result.stdout)

    # Remove some values to reduce output verbosity.
    for match in grype_result.get('matches', []):
        try:
            del match['artifact']
        except KeyError:
            pass
        try:
            del match['relatedVulnerabilities']
        except KeyError:
            pass

    return grype_result

# Remove image.
# This function never raises an exception, it just logs the failure in the
# global errors object.
def remove_image(docker_client: DockerClient, image:str):
    try:
        logger.info(f"[{image}] - Removing image")
        docker_client.images.remove(image, force=True)
    except Exception as e:
        logger.error(
            f"[{image}] - Error removing image: {str(e)}"
        )
        add_error("remove_image", image)

def process_image(image: Dict[str, Any], timestamp:str, output_dir:str) -> Optional[Dict[str, Any]]:
    image_name: str = image["name"]
    updated_image_name: str = f"{image['name']}-updated"
    logger.info(f"[{image_name}] - Processing image")

    docker_client: DockerClient = docker.from_env()
    # Try block just to make sure we close the docker client.
    try:
        try:
            update_and_create_new_image(
                docker_client, image_name
            )
        except Exception as e:
            # if e.msg == "failed when pulling container":
            #     errors["pull"].append("image_name")
            # remove re-raise
            return None

        try:
            scan_result: Dict[str, Any] = scan_image_with_grype(
                updated_image_name
            )
        except Exception as e:
            logger.error(f"[{image_name}] - Error scanning: {e}")
            add_error("scan", image_name)
            return None

        # We don't need the images anymore, remove them.
        remove_image(docker_client, image_name)
        remove_image(docker_client, updated_image_name)

        vulnerabilities: List[Dict[str, Any]] = scan_result.get("matches", [])
        cve_count: int = sum(
            1
            for match in vulnerabilities
            if match.get("vulnerability", {}).get("id", "").startswith("CVE-")
        )

        report: Dict[str, Any] = {
            "image_name": image_name,
            "updated_image_name": updated_image_name,
            "pull_count": image["pull_count"],
            "star_count": image["star_count"],
            "scan_timestamp": timestamp,
            "total_vulnerabilities": len(vulnerabilities),
            "cve_count": cve_count,
            "scan_result": scan_result,
        }

        # Save individual report
        report_file: str = os.path.join(
            output_dir, f"{image_name.replace(':', '_').replace('/', '_')}_cve_report.json"
        )
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"[{image_name}] - Completed processing")
        return report
    except Exception as e:
        logger.error(f"[{image_name}] - Unexpected error: {e}")
        add_error("other", image_name)
    finally:
        docker_client.close()

def generate_cve_report(
    images_to_check: str,
    max_images: int,
) -> None:
    logger.info("Starting CVE report generation")

    # Generate timestamp and create date-based subfolder
    current_date: datetime.datetime = datetime.datetime.now()
    date_subfolder: str = current_date.strftime("%Y/%m/%d")
    output_dir: str = os.path.join("cve_reports", date_subfolder)
    os.makedirs(output_dir, exist_ok=True)

    timestamp: str = current_date.isoformat()

    # Read the input file
    logger.info(f"Reading input file: {images_to_check}")
    with open(images_to_check, "r") as f:
        docker_images: List[Dict[str, Any]] = json.load(f)

    # Limit the number of images
    logger.info(f"Limiting scan to {max_images} images")
    docker_images = docker_images[:max_images]

    # Get the number of CPU threads
    num_workers = multiprocessing.cpu_count()
    logger.info(f"Using {num_workers} workers for parallel processing")

    logger.debug("Starting parallel image processing")
    # Use ThreadPoolExecutor to parallelize the scanning process
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_image: Dict[Any, Dict[str, Any]] = {
            executor.submit(process_image, image, timestamp, output_dir): image for image in docker_images
        }

        all_reports: List[Dict[str, Any]] = []
        for future in as_completed(future_to_image):
            report: Optional[Dict[str, Any]] = future.result()
            if report:
                all_reports.append(report)

    logger.info("Completed parallel image processing")

    # Sort reports by CVE count (descending)
    all_reports.sort(key=lambda x: x["cve_count"], reverse=True)

    logger.info("Generating summary report")
    # Generate summary report
    summary_report: Dict[str, Any] = {
        "timestamp": timestamp,
        "total_images_scanned": len(docker_images),
        "images_with_vulnerabilities": len(all_reports),
        "total_vulnerabilities_found": sum(
            report["total_vulnerabilities"] for report in all_reports
        ),
        "total_cves_found": sum(report["cve_count"] for report in all_reports),
        "all_scanned_images": [
            {
                "image_name": report["image_name"],
                "updated_image_name": report["updated_image_name"],
                "cve_count": report["cve_count"],
                "total_vulnerabilities": report["total_vulnerabilities"],
            }
            for report in all_reports
        ],
    }
    summary_report.update({"errors": get_errors()})

    # Save summary report
    summary_file: str = os.path.join(output_dir, "summary_cve_report.json")
    with open(summary_file, "w") as f:
        json.dump(summary_report, f, indent=2)

    logger.info(f"CVE reports generated and saved in {output_dir}")
    logger.info(f"Summary report saved as {summary_file}")
    logger.info(f"Errors: {get_errors()}")


if __name__ == "__main__":
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Generate CVE reports for container images."
    )
    parser.add_argument(
        "--max-images-to-check",
        type=int,
        default=15,
        help="Maximum number of images to check (default: 15)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--images-to-check",
        type=str,
        default="official_docker_images.json",
        help="Input file containing Docker images (default: official_docker_images.json)",
    )
    args: argparse.Namespace = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    generate_cve_report(images_to_check=args.images_to_check, max_images=args.max_images_to_check)
