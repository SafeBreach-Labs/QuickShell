@echo off
REM Set the repository URL and specific commit hash
set REPO_URL=https://github.com/googleprojectzero/winafl.git
set COMMIT_HASH=092c47b5bcf57607fd659af21dbc2c05cb92f16e
set PATCH_FILE=afl_fuzz_no_trimming.patch

REM Clone the repository
echo Cloning the repository...
git clone %REPO_URL%
if %ERRORLEVEL% NEQ 0 (
    echo Failed to clone the repository.
    exit /b 1
)

REM Change directory to the cloned repository
cd winafl

REM Checkout the specific commit
echo Checking out the specified commit...
git checkout %COMMIT_HASH%
if %ERRORLEVEL% NEQ 0 (
    echo Failed to checkout the specified commit.
    exit /b 1
)

REM Apply the patch
echo Applying the patch...
git apply ..\%PATCH_FILE%
if %ERRORLEVEL% NEQ 0 (
    echo Failed to apply the patch.
    exit /b 1
)

echo Patch applied successfully.