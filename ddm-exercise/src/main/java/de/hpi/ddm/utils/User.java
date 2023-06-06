package de.hpi.ddm.utils;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private int id;
    private String name;
    // all character that can be present in the password (i.e. "ABCDEFGHIJK")
    private String passwordChars;
    private int passwordLength;
    private String hashedPassword;
    private String[] hashedHints;
}
