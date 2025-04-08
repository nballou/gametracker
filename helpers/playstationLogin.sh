#!/bin/bash
# Log into PlayStation via ADB automation

adb shell input tap 518 2150   # Click "sign in"
sleep 3

adb shell input tap 440 870    # Click email box
sleep 2

adb shell input text "nick@nickballou.com"
sleep 2

adb shell input tap 513 1000   # Click "next"
sleep 3

adb shell input tap 480 970    # Click email box (again for password)
sleep 2

adb shell input text "docbuz-Duwce4-woshib"
sleep 2

adb shell input tap 770 1100   # Click "sign in"
sleep 10

adb shell input tap 650 2000   # Click "confirm and continue"
sleep 2