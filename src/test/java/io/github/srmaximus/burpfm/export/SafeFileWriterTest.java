// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SafeFileWriterTest {
    @TempDir
    Path directory;

    @Test
    void appendsExpectedExtensionAndRefusesImplicitOverwrite() throws Exception {
        Path output = SafeFileWriter.write(directory.resolve("report"), ".json", "one", false);
        assertEquals("one", Files.readString(output));
        assertThrows(IOException.class, () -> SafeFileWriter.write(directory.resolve("report"), ".json", "two", false));
        SafeFileWriter.write(directory.resolve("report"), ".json", "two", true);
        assertEquals("two", Files.readString(output));
    }

    @Test
    void refusesSymbolicLinkTargets() throws Exception {
        Path destination = directory.resolve("destination.json");
        Files.writeString(destination, "safe");
        Path link = directory.resolve("link.json");
        Files.createSymbolicLink(link, destination);
        assertThrows(IOException.class, () -> SafeFileWriter.write(link, ".json", "unsafe", true));
        assertEquals("safe", Files.readString(destination));
    }
}
