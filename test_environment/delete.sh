#!/usr/bin/bash -eu

REPOS=("basic" "rules" "radioactive")

for REPO in ${REPOS[*]}; do
  echo "HTTP DELETE https://api.github.com/repos/${GH_USER}/committee-${REPO}"
  curl --header "Authorization: token ${GH_TOKEN}" -X DELETE https://api.github.com/repos/${GH_USER}/committee-${REPO}
  rm -rf "committee-${REPO}"
done
