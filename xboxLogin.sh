#!/bin/bash
# Log into Xbox via ADB automation

adb shell input tap 550 1950
sleep 3
adb shell input tap 280 530 # click email box
sleep 2
adb shell input text "nick@nickballou.com"
sleep 2
adb shell input tap 870 812 # click next
sleep 2
adb shell input tap 360 570 # click password box
sleep 2
adb shell input text "guqtin-Conjen-turni6"
sleep 2
adb shell input tap 900 920 # click sign in
sleep 5
adb shell input tap 550 2145 # click “let’s go”
sleep 2
