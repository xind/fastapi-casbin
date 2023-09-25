#!/bin/bash

# Build Docker Compose services
docker compose build

# Run setup script inside the fastapi service container to initialize database
docker compose run --rm fastapi python3 setup.py

# Start Docker Compose services in detached mode
docker compose up -d
