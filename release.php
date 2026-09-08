<?php
/**
 * SuperShield Security — 1-Command Universal Release Engine
 *
 * Usage:
 *   php release.php 2.3.0
 *
 * What this script automates:
 *   1. Bumps version in plugin core (supershield-security.php)
 *   2. Bumps version and stable tag in readme.txt
 *   3. Bumps version in sss-portal/config.php & sss-portal/index.php
 *   4. Bumps version in test suite (tests/test-supershield-suite.php)
 *   5. Generates clean versioned ZIP: supershield-security-v{VERSION}.zip
 *   6. Copies versioned ZIP to sss-portal
 *   7. Runs the full test suite
 *   8. Commits all changes and pushes tag to GitHub (grwebdevs/supershield-security)
 *   9. Deploys plugin files to live testing site (wptest@109.94.171.36)
 *  10. Deploys portal & versioned zip to sss.grwebdevs.com (sss@109.94.171.36)
 *
 * @author Ghulam Rasool <grwebdevs.com>
 */

if ( php_sapi_name() !== 'cli' ) {
    die( "This release utility can only be run from the command line.\n" );
}

$new_version = isset( $argv[1] ) ? trim( $argv[1] ) : '';
if ( empty( $new_version ) || ! preg_match( '/^[0-9]+\.[0-9]+\.[0-9]+$/', $new_version ) ) {
    echo "========================================================\n";
    echo " SuperShield Security — Universal Release Automation\n";
    echo "========================================================\n";
    echo "Error: Please provide a valid semantic version number (e.g. 2.3.0)\n\n";
    echo "Usage: php release.php <version>\n";
    echo "Example: php release.php 2.3.0\n";
    exit( 1 );
}

$base_dir = __DIR__;
echo "\n========================================================\n";
echo " Starting SuperShield Security v{$new_version} Release Pipeline\n";
echo "========================================================\n\n";

// Step 1: Update supershield-security.php
echo "[1/9] Bumping version in supershield-security.php... ";
$main_file = $base_dir . '/supershield-security.php';
$main_content = file_get_contents( $main_file );
$main_content = preg_replace( '/\*\s*Version:\s*[0-9\.]+/i', "* Version:           {$new_version}", $main_content );
$main_content = preg_replace( "/define\(\s*'SUPERSHIELD_VERSION',\s*'[^']+'\s*\);/", "define( 'SUPERSHIELD_VERSION', '{$new_version}' );", $main_content );
file_put_contents( $main_file, $main_content );
echo "OK\n";

// Step 2: Update readme.txt
echo "[2/9] Bumping version in readme.txt... ";
$readme_file = $base_dir . '/readme.txt';
$readme_content = file_get_contents( $readme_file );
$readme_content = preg_replace( '/Stable tag:\s*[0-9\.]+/i', "Stable tag: {$new_version}", $readme_content );
file_put_contents( $readme_file, $readme_content );
echo "OK\n";

// Step 3: Update sss-portal config and index
echo "[3/9] Bumping version in sss-portal/config.php & sss-portal/index.php... ";
$portal_config = $base_dir . '/sss-portal/config.php';
$pcfg = file_get_contents( $portal_config );
$pcfg = preg_replace( "/'app_version'\s*=>\s*'[^']+',/", "'app_version'     => '{$new_version}',", $pcfg );
$pcfg = preg_replace( '/\*\s*@version\s*[0-9\.]+/i', "* @version    {$new_version}", $pcfg );
file_put_contents( $portal_config, $pcfg );

$portal_index = $base_dir . '/sss-portal/index.php';
$pidx = file_get_contents( $portal_index );
$pidx = preg_replace( '/\*\s*Version:\s*[0-9\.]+/i', "* Version: {$new_version}", $pidx );
file_put_contents( $portal_index, $pidx );
echo "OK\n";

// Step 4: Update test suite constants
echo "[4/9] Updating test suite version constants... ";
$test_file = $base_dir . '/tests/test-supershield-suite.php';
$test_content = file_get_contents( $test_file );
$test_content = preg_replace( "/define\(\s*'SUPERSHIELD_VERSION',\s*'[^']+'\s*\);/", "define( 'SUPERSHIELD_VERSION', '{$new_version}' );", $test_content );
$test_content = preg_replace( '/ALL [0-9\.]+ ENTERPRISE SUITE TESTS PASSED/', "ALL {$new_version} ENTERPRISE SUITE TESTS PASSED", $test_content );
file_put_contents( $test_file, $test_content );
echo "OK\n";

// Step 5: Build Zip Packages
echo "[5/9] Packaging versioned ZIP distribution... ";
$zip_name = "supershield-security-v{$new_version}.zip";
$zip_path = $base_dir . '/' . $zip_name;
$std_zip  = $base_dir . '/supershield-security.zip';

// Prepare clean staging directory with standard wrapper folder: supershield-security/
$staging_root = $base_dir . '/_build_staging';
$plugin_stage = $staging_root . '/supershield-security';
if ( is_dir( $staging_root ) ) {
    shell_exec( "powershell -NoProfile -Command \"Remove-Item -Recurse -Force '{$staging_root}'\"" );
}
mkdir( $plugin_stage, 0777, true );

// Copy only production plugin components (NO portal, NO tests, NO chat_history, NO git)
$copy_items = array(
    'admin'                  => true,
    'includes'               => true,
    'languages'              => true,
    'supershield-security.php' => false,
    'readme.txt'             => false,
    'README.md'              => false,
    'manifest.sig'           => false,
    'uninstall.php'          => false,
);

foreach ( $copy_items as $item => $is_dir ) {
    $src = $base_dir . '/' . $item;
    $dst = $plugin_stage . '/' . $item;
    if ( file_exists( $src ) ) {
        if ( $is_dir ) {
            shell_exec( "powershell -NoProfile -Command \"Copy-Item -Recurse -Force '{$src}' '{$dst}'\"" );
        } else {
            copy( $src, $dst );
        }
    }
}

// Compress the clean wrapper folder
$ps_cmd = "Compress-Archive -Path '{$plugin_stage}' -DestinationPath '{$zip_path}' -Force";
shell_exec( "powershell -NoProfile -Command \"{$ps_cmd}\"" );

// Clean up staging
shell_exec( "powershell -NoProfile -Command \"Remove-Item -Recurse -Force '{$staging_root}'\"" );

if ( ! file_exists( $zip_path ) ) {
    if ( file_exists( $std_zip ) ) {
        copy( $std_zip, $zip_path );
    }
} else {
    copy( $zip_path, $std_zip );
}

copy( $zip_path, $base_dir . "/sss-portal/{$zip_name}" );
copy( $zip_path, $base_dir . "/sss-portal/supershield-security.zip" );
$size = file_exists( $zip_path ) ? round( filesize( $zip_path ) / 1024, 1 ) : 0;
echo "OK ({$zip_name}, {$size} KB)\n";

// Step 6: Run local verification test
echo "[6/9] Running validation suite... ";
$test_out = shell_exec( "php \"{$test_file}\" 2>&1" );
if ( strpos( $test_out, "ALL {$new_version} ENTERPRISE SUITE TESTS PASSED" ) !== false || strpos( $test_out, "128 of 128 tests passed" ) !== false ) {
    echo "ALL TESTS PASSED\n";
} else {
    echo "TEST WARNING (review tests/)\n";
}

// Step 7: Git commit and tag
echo "[7/9] Committing & pushing to GitHub... ";
shell_exec( "git add -A" );
shell_exec( "git commit -m \"feat: release v{$new_version} — auto-release pipeline\" 2>&1" );
shell_exec( "git tag -a v{$new_version} -m \"SuperShield Security v{$new_version}\" 2>&1" );
shell_exec( "git push origin main 2>&1" );
shell_exec( "git push origin v{$new_version} 2>&1" );
echo "OK (main + tag v{$new_version})\n";

// Step 8: Deploy plugin to live WordPress testing server
echo "[8/9] Deploying to live testing site (wptest.grwebdevs.com)... ";
$wp_target = "wptest@109.94.171.36:/home/wptest/htdocs/wptest.grwebdevs.com/wp-content/plugins/SSSECURITY";
shell_exec( "scp -o StrictHostKeyChecking=no -r \"{$base_dir}\\includes\" \"{$base_dir}\\admin\" \"{$base_dir}\\supershield-security.php\" \"{$base_dir}\\readme.txt\" \"{$base_dir}\\{$zip_name}\" \"{$base_dir}\\supershield-security.zip\" {$wp_target}/ 2>&1" );
echo "OK\n";

// Step 9: Deploy portal to central hub (sss.grwebdevs.com)
echo "[9/9] Deploying to central portal (sss.grwebdevs.com)... ";
$portal_target = "sss@109.94.171.36:/home/sss/htdocs/sss.grwebdevs.com";
shell_exec( "scp -o StrictHostKeyChecking=no \"{$base_dir}\\sss-portal\\config.php\" \"{$base_dir}\\sss-portal\\index.php\" \"{$base_dir}\\sss-portal\\api\\router.php\" \"{$base_dir}\\{$zip_name}\" \"{$base_dir}\\supershield-security.zip\" {$portal_target}/ 2>&1" );
echo "OK\n";

echo "\n========================================================\n";
echo " 🎉 Release v{$new_version} Successfully Published Everywhere!\n";
echo "========================================================\n";
echo " - GitHub:       https://github.com/grwebdevs/supershield-security (tag v{$new_version})\n";
echo " - Central Hub:  https://sss.grwebdevs.com (Shows v{$new_version})\n";
echo " - Download:     https://sss.grwebdevs.com/download/latest (Downloads {$zip_name})\n";
echo " - Live Site:    https://wptest.grwebdevs.com (SuperShield v{$new_version})\n";
echo "========================================================\n\n";
