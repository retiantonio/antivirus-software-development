<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
</head>
<body>

<h1 align="center">🛡️ Linux-Based Antivirus</h1>

<p align="center">
  <strong>Real-Time Malware Detection & Automated Quarantine Tool</strong><br>
  Built in C using libyara, inotify, and POSIX
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C11-00599C?style=flat-square&logo=c" alt="C">
  <img src="https://img.shields.io/badge/Security-YARA%20API-red?style=flat-square" alt="YARA">
  <img src="https://img.shields.io/badge/Platform-Linux%20Kernel-FCC624?style=flat-square&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/Architecture-Multithreaded-brightgreen?style=flat-square" alt="Architecture">
</p>

<hr>

<h3>📖 Overview</h3>
<p>
  Implemented a Linux-based antivirus engine in C, integrating <b>Total Virus’s YARA API</b> for signature-based detection and leveraging low-level system calls for <b>efficient file scanning</b>, <b>real-time threat analysis</b> and <b>threat mitigation through a quarantine zone</b>. Optimized for performance and extensibility, enabling rapid detection of malware samples and custom YARA rules.
</p>

<h3>🚀 Implementation Features</h3>
<ul>
  <li><b>Multithreaded Directory Watcher:</b> Utilizes <code>pthread</code> and <code>inotify_init</code> to monitor multiple directories concurrently. Each watch path is handled by a dedicated thread, ensuring zero latency between file creation and detection.</li>
  <li><b>Isolated Scanning Engine:</b> Implements a <b>Fork-Exec model</b>. The monitor daemon spawns an independent child process for every scan using <code>fork()</code> and <code>execl()</code>, isolating the main daemon from the resource-heavy scanning logic.</li>
  <li><b>Custom Recursive Crawler:</b> Features a manual directory traversal engine using <code>opendir</code> and <code>readdir</code>, capable of deep-scanning entire file-tree structures recursively.</li>
  <li><b>Manual Quarantine Lifecycle:</b>
    <ul>
      <li><b>Data Migration:</b> Implements a chunk-based copy loop using <code>open(2)</code> and <code>write(2)</code> to move threats to a secure zone without overloading system memory.</li>
      <li><b>Atomic Neutralization:</b> Uses <code>unlink(2)</code> to remove the source file only after a successful quarantine copy is verified.</li>
    </ul>
  </li>
  <li><b>Dynamic YARA Integration:</b> Dynamically crawls and compiles <code>.yar</code> rule files into binary signatures at runtime for high-speed pattern matching.</li>
</ul>

<h3>🏗️ Technical Deep-Dive</h3>

<table width="100%">
  <tr>
    <th align="left" width="25%">Feature</th>
    <th align="left" width="35%">Linux System Call / API</th>
    <th align="left" width="40%">Technical Purpose</th>
  </tr>
  <tr>
    <td><b>Real-Time Events</b></td>
    <td><code>inotify_add_watch</code></td>
    <td>Instantaneous <code>IN_CREATE</code> event capture for live file monitoring.</td>
  </tr>
  <tr>
    <td><b>Process Isolation</b></td>
    <td><code>fork</code> / <code>waitpid</code></td>
    <td>Sandboxing the scanner to prevent engine crashes from affecting the daemon.</td>
  </tr>
  <tr>
    <td><b>Threat Mitigation</b></td>
    <td><code>unlink(2)</code></td>
    <td>Hard-removal of malicious file links from the user-accessible filesystem.</td>
  </tr>
  <tr>
    <td><b>File I/O</b></td>
    <td><code>read</code> (512b Chunks)</td>
    <td>Optimized data streaming to handle large malware samples safely.</td>
  </tr>
  <tr>
    <td><b>Concurrency</b></td>
    <td><code>pthreads</code></td>
    <td>Parallel surveillance of multiple sensitive system paths simultaneously.</td>
  </tr>
</table>



<h3>🛠️ Usage</h3>

<pre><code>
# 1. Install libyara dependency
sudo apt-get install libyara-dev

# 2. Compile the Engine and Monitor
gcc ./antivirusengine.c -lyara -o antivirusengineexecutable
gcc ./real-time-monitoring.c -lpthread -o real-time-monitoring-executable

# 3. Start monitoring multiple directories (semicolon separated)
./real-time-monitoring-executable "/home/user/Downloads/;/home/user/Music/"

# 4. Output when adding or updating a file in the given directories
    ....
[SCANNING] Did not match rule: APT9002Code
[SCANNING] Did not match rule: APT9002Strings
[SCANNING] Did not match rule: APT9002
[SCANNING] Did not match rule: FE_APT_9002
[SCANNING] Did not match rule: PolishBankRAT_srservice_xorloop
[SCANNING] Did not match rule: PolishBankRAT_fdsvc_xor_loop

[RESULT] Scan finished
[RESULT] Rules Not Matched: 2277
[RESULT] Rules Matched: 1 # myTestRule.yar always matches - rule for testing
[RESULT] Detections: 1 | File may be dangerous to your computer
[IN PROGRESS] Moving File
[SUCCESS] Moved File to Quarantine
</code></pre>


<hr>

<p align="center">
  <b>Developed by Reti Antonio</b><br>
  <i>Focusing on Malware Analysis and Cyber Security</i>
</p>

</body>
</html>
