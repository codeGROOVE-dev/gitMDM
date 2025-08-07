#!/bin/sh
PROJECT="git-mdm"
export KO_DOCKER_REPO="gcr.io/${PROJECT}/git-mdm"

gcloud run deploy git-mdm --image="$(ko publish ./cmd/server/)" --region us-central1 --project "${PROJECT}"
