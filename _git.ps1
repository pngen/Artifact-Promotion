$log = 'E:\ap-git.txt'
git add -A 2>&1 | Out-File -Encoding utf8 $log
git -c user.name='Summon Software Labs' -c user.email='release@summonsoftwarelabs.invalid' commit -q -m 'Artifact Promotion 1.0.0' 2>&1 | Out-File -Encoding utf8 -Append $log
('COMMIT ' + $LASTEXITCODE) | Out-File -Encoding utf8 -Append $log
git tag -a v1.0.0 -m 'Artifact Promotion 1.0.0' 2>&1 | Out-File -Encoding utf8 -Append $log
('TAG ' + $LASTEXITCODE) | Out-File -Encoding utf8 -Append $log
git log --oneline -1 2>&1 | Out-File -Encoding utf8 -Append $log
git rev-parse HEAD 2>&1 | Out-File -Encoding utf8 -Append $log
git rev-parse v1.0.0 2>&1 | Out-File -Encoding utf8 -Append $log
git status --porcelain 2>&1 | Out-File -Encoding utf8 -Append $log
git remote -v 2>&1 | Out-File -Encoding utf8 -Append $log
git push -u origin main 2>&1 | Out-File -Encoding utf8 -Append $log
('PUSH ' + $LASTEXITCODE) | Out-File -Encoding utf8 -Append $log
git push origin v1.0.0 2>&1 | Out-File -Encoding utf8 -Append $log
('PUSHTAG ' + $LASTEXITCODE) | Out-File -Encoding utf8 -Append $log
git ls-remote origin refs/heads/main refs/tags/v1.0.0 2>&1 | Out-File -Encoding utf8 -Append $log