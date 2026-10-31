# VHS v0.12.1. Start the WP-style lab without a supervisor before rendering.
Output docs/assets/demos/wp-cms-dos.gif
Output docs/assets/demos/wp-cms-dos.mp4
Output docs/assets/demos/wp-cms-dos.ascii

Set Shell "powershell"
Set Width 1200
Set Height 700
Set FontSize 18
Set TypingSpeed 20 ms
Set Framerate 10
Set PlaybackSpeed 2

Type "python -u poc.py --profile n2s-wp-24.22.0-x86_64 --mode dos --timeout 30"
Enter
Wait+Screen@120s /PASS: DoS verified/
Wait+Screen@15s /healthchecks_failed=4\/4/
Sleep 3s
