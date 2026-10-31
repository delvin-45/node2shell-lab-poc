# VHS v0.12.1. Start deploy/compose.scan.yaml before rendering.
Output docs/assets/demos/passive-scan.gif
Output docs/assets/demos/passive-scan.mp4
Output docs/assets/demos/passive-scan.ascii

Set Shell "powershell"
Set Width 1200
Set Height 700
Set FontSize 18
Set TypingSpeed 15 ms
Set Framerate 10
Set PlaybackSpeed 2

Type "python tools/scan.py --assets deploy/targets.txt"
Enter
Wait+Screen@60s /summary/
Sleep 4s
