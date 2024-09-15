# Freedump (free as in beer 🍺)

Freedump is a library and cli tool that allow you to read/write/dump the memory of a process via Frida, and also to manipulate a dump
later locally for quick search.

Right now, it has been tested only for Linux/Android but I guess it should be trivial to add the support for Windows/OSX.

Freedump is composed of some tricks to speed up the access via Frida of the memory, and to have a unify library for researcher (as it is a common case).

On some case, like to dump the entire process memory range on Android, it will reduce the time to wait, from 1/2 minutes to few seconds (no benchmark sorry, just trust me).

## Requirements

## Installation

## Usage

Please send any PR for improvements or to fix any bugs, add new features.

***For my father, Andre Desnos (13/10/1947 - 02/09/2024)***
