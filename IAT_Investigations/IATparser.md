Goal

This is a small exercise to to learn how to access and iterate through the IAT table for a process. Hypothetically, one can overwrite an IAT entry (after ```VirtualProtect``` it to be executable) so that a particular function call
gets redirected to an arbitrary function address.

Build

```cl IATparser.c```
