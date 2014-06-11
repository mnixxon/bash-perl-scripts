#! /bin/bash
find . | grep -v AppleDouble | rename s/"\[\ www.Torrenting.com\ \]\ -\ "//i
find . | grep -v AppleDouble | rename s/"\[\ www.Speed.Cd\ \]\ -\ "//i
find . | grep -v AppleDouble | rename s/"-2hd"//i
find . | grep -v AppleDouble | rename s/"-dimension"//i
find . | grep -v AppleDouble | rename s/"-killers"//i
find . | grep -v AppleDouble | rename s/"-immerse"//i
find . | grep -v AppleDouble | rename s/"-evolve"//i
find . | grep -v AppleDouble | rename s/"-publichd"//i
find . | grep -v AppleDouble | rename s/"-avs"//i
find . | grep -v AppleDouble | rename s/"-river"//i
find . | grep -v AppleDouble | rename s/"-esir"//i
find . | grep -v AppleDouble | rename s/"-lol"//i
find . | grep -v AppleDouble | rename s/"-remarkable"//i
find . | grep -v AppleDouble | rename s/"-excellence"//i

