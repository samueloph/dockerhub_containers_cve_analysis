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

import requests
import json
from operator import itemgetter
import time
import logging
import colorlog
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def setup_logger():
    """Set up the colored logger."""
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    ))

    logger = colorlog.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

logger = setup_logger()

def update_url_query(url, params):
    """Update the query parameters of a URL."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params.update(params)
    updated_query = urlencode(query_params, doseq=True)
    return urlunparse(parsed_url._replace(query=updated_query))

def get_all_official_docker_images():
    base_url = "https://hub.docker.com/v2/repositories/library/"
    images = []
    next_url = update_url_query(base_url, {'page_size': '100'})
    page = 1

    while next_url:
        logger.info(f"Fetching page {page} of official Docker images...")
        response = requests.get(next_url)
        data = response.json()

        for i, image in enumerate(data['results'], 1):
            logger.debug(f"Processing image {i}/{len(data['results'])} on page {page}: {image['name']}")

            images.append({
                'name': image['name'],
                'pull_count': image['pull_count'],
                'star_count': image['star_count']
            })

        next_url = data.get('next')
        if next_url:
            next_url = update_url_query(next_url, {'page_size': '100'})
        page += 1

    # Sort the images by pull count
    logger.info("Sorting images by pull count...")
    return sorted(images, key=itemgetter('pull_count'), reverse=True)

def save_to_json(data, filename='official_docker_images.json'):
    logger.info(f"Saving data to {filename}...")
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    logger.info("Starting to fetch all official Docker Hub images. This may take a while...")
    start_time = time.time()

    images = get_all_official_docker_images()

    logger.info(f"Found {len(images)} official images.")

    save_to_json(images)
    logger.info(f"Data saved to official_docker_images.json")

    # Print top 10 as a sample
    logger.info("\nTop 10 images by pull count:")
    for i, image in enumerate(images[:10], 1):
        logger.info(f"{i}. {image['name']}")
        logger.info(f"   Pulls: {image['pull_count']:,}")
        logger.info(f"   Stars: {image['star_count']:,}")
        print()

    end_time = time.time()
    logger.info(f"Total execution time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
