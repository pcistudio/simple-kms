package com.pcistudio.kms.util;

import java.util.List;

public enum StaticKeys {
    DEFAULT(List.of("WgBhmFfd+SN2mw6GjCjJ2J9xDtPSoQXUQ+gf6Rc397c="), List.of("3jFdaAHNNiCoDNTIhKI7jLF2FejoOaWvapnZ501gdko=")),
    DEFAULT_TWO_KEYS(List.of("WgBhmFfd+SN2mw6GjCjJ2J9xDtPSoQXUQ+gf6Rc397c="), List.of("HbIyfXFZPiWMnmU8psHTixDjBf6LwKqlLOOX22dadkQ=", "d1jqEQB2zjl8w2e4/BT/9u9wVrJ5xiLCBkHHZVNRr98=")),
    DEFAULT_THREE_KEYS(List.of("WgBhmFfd+SN2mw6GjCjJ2J9xDtPSoQXUQ+gf6Rc397c="), List.of("Sw4Xup3CpSZEiXZeBrYEezP3fwU/Bw8lT5b2xE00iIE=", "PnrJABZeZ0ocndsJcpyKzDG+Opf40RAzwc3l0DV0YoY=", "fChgRpwoNi9na0Y7E/A2ICukODdnIuhjF2TzKcPVrn0=")),

    TWO_KEYS(List.of("2IaR/Ogo1DA1JTe6Hg6X+MtVspY+8eSTTC1fekKRIaE="), List.of("bBrW8u58dx1tPwf090TtoapwOQMXJWG6lR+3Lb8D0FU=", "OsaD3/duhmWsEVaZXBM7bAdaZCZ0l6nZlKJIxLCsSbk=")),
    THREE_KEYS(List.of("xX3s69RJ5pkNx2ft8Y88XEscOPbe6e3oxfFfyHFPmcc="), List.of("/6SBRNhe6L8rzrYWOPQxHSYLYBQlGOZhF+/06P0kT/8=", "MlA1mE4fM+iuq7hf5L18ohGk2W3yywMcOgpiLeiZz9c=", "uYoBy5w/7v1Y7uR6ZMPzxcEhaDhOzAWNLIZhCwtuANE=")),
    TWO_MASTER_KEYS(List.of("C4U3ufCbCFpeFmR7G0juB83F6lkEMbhZ7rXYvYiC2cw=", "6muACAvwLdAq0kS068EvAjN5f0Li6Tce/atVq+cC57A="), List.of("bBrW8u58dx1tPwf090TtoapwOQMXJWG6lR+3Lb8D0FU=", "OsaD3/duhmWsEVaZXBM7bAdaZCZ0l6nZlKJIxLCsSbk=")),
    THREE_MASTER_KEYS(List.of("MkduXHEOrtuLPzLlPaxoHL0G4I5PVYa2bIESRq6vub0=", "RM0mgHARJOH19LyaGtJ2J/yzEX2osi6vVSBHE/SqEdg=", "uLAlpKewEoE9tcnjPeZoN6xOSOySjwJvHMra63i+Y5c="), List.of("bBrW8u58dx1tPwf090TtoapwOQMXJWG6lR+3Lb8D0FU=", "OsaD3/duhmWsEVaZXBM7bAdaZCZ0l6nZlKJIxLCsSbk="));

    private List<String> masterKeys;
    private List<String> keys;

    StaticKeys(List<String> masterKeys, List<String> keys) {
        this.masterKeys = masterKeys;
        this.keys = keys;
    }

    public List<String> getMasterKeys() {
        return masterKeys;
    }

    public List<String> getKeys() {
        return keys;
    }
}