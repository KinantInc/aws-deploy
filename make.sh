pyinstaller -F awsAMIdeploy/deploy.py

echo ''
echo 'Location of binaries:'
ls -lh dist/deploy
