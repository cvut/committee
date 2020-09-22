#!/usr/bin/bash -eux

# this var is used by hub, it will use the same token = same user
export GITHUB_TOKEN=${GH_TOKEN}

# basic repository with few commits in two branches
mkdir committee-basic
cd committee-basic
git init
hub create

# add README.md
printf "# Committee (BASIC)\n\nThis repo is used for basic tests...\n" > README.md
git add README.md
git commit -m "Add README.md"
git push -q -u origin master

# add something in other branch
git checkout -b other
printf "This is the other branch\n" > NOTE.txt
git add NOTE.txt
git commit -m "Add branch note"
git push -q origin other

# add something in other branch
git checkout master
git checkout -b feature/xyz
printf "Here is a super new feature XYZ\n" > CHANGELOG
git add CHANGELOG
git commit -m "Add XYZ feature"
git push -q origin feature/xyz
git tag xyz
git push origin xyz

# add something in other branch
git checkout master
git checkout -b feature/abc
printf "Here is a super new feature ABC\n" > CHANGELOG
git add CHANGELOG
git commit -m "Add ABC feature"
git push -q origin feature/abc
git tag abc
git push origin abc

# some paths in master
git checkout master
mkdir test
printf "Test 1\n" > test/file1
printf "Test 2\n" > test/file2
printf "Test 3\n" > test/file3
git add test/*
git commit -m "Add test files"
printf "\n\nUpdate in test 2\n" >> test/file2
git add test/file2
git commit -m "Update in test file 2"
git rm test/file3
git commit -m "Removing test file 3"
git push -q origin master

cd ..

# repository to test various rules
mkdir committee-rules
cd committee-rules
git init
hub create

printf "# Committee (RULES)\n\nThis repo is used for basic tests...\n" > README.md
git add README.md
git commit -m "Initial commit"

printf "You are not allowed to do anything with this!\n" > LICENSE
git add LICENSE
git commit -m "Add LICENSE"

touch cant-touch-this
printf "This is some dummy file\nthe same as foo and bar\n" > dummy.txt
printf "🔝💩\n" > topshit.txt
for I in {1..666}; do
  printf "You Only Live Once\n" >> yolo.txt
done
git add cant-touch-this dummy.txt topshit.txt yolo.txt
git commit -m "Add various files"

printf "" > yolo.txt
for I in {1..333}; do
  printf "You Only Live Once\n" >> yolo.txt
  printf "You Only Die Once\n" >> yolo.txt
done
git add yolo.txt
git commit -m "Not so much yolo anymore, also yodo"

git rm ./*.txt README.md
git commit -m "Fuck off this junk"

mkdir lists
printf "suchama4\nhroncmir\nHe Who Must Not Be Named\n" > lists/whitelist.txt
printf "infomail\nhelpdesk\nAdmiral Ackbar\nVoldemort\n" > lists/blacklist.txt
git add lists/blacklist.txt lists/whitelist.txt
git commit -m "My precious lists based on general knowledge"

git push -q -u origin master

cd ..

# radioactive waste repository
# - just simple 111 commits in default branch
mkdir committee-radioactive
cd committee-radioactive
git init
hub create

for I in {1..111}; do
  printf "This is line #$I of the waste\n" >> WASTE
  git add WASTE
  git commit -q -m "Waste number $I"
done
git push -q -u origin master

cd ..
