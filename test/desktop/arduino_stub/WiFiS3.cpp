#include "WiFiS3.h"

WiFiClass WiFi;

// Test hooks, see WiFiS3.h.
int WiFiClass::begin_calls = 0;
bool WiFiClass::force_down = false;
