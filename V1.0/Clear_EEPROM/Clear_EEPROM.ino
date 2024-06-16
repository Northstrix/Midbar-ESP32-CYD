/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar-esp32-cyd/
https://github.com/Northstrix/Midbar-ESP32-CYD
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
*/
#include <EEPROM.h>

#define EEPROM_SIZE 511

void setup()
{
  EEPROM.begin(EEPROM_SIZE);
  for (unsigned int i = 0; i < EEPROM_SIZE; i++ )
    EEPROM.write(0, 0);
  EEPROM.end();

}

void loop() { } 
