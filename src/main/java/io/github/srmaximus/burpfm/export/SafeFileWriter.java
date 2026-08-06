// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class SafeFileWriter {
    private SafeFileWriter() {
    }

    public static Path write(Path requested, String expectedExtension, String content, boolean allowOverwrite)
            throws IOException {
        if (requested == null || expectedExtension == null || expectedExtension.isBlank()) {
            throw new IllegalArgumentException("Export path and extension are required");
        }
        Path target = requested.toAbsolutePath().normalize();
        Path fileName = target.getFileName();
        if (fileName == null) {
            throw new IOException("Export target must be a file path");
        }
        if (!fileName.toString().toLowerCase(java.util.Locale.ROOT)
                .endsWith(expectedExtension.toLowerCase(java.util.Locale.ROOT))) {
            target = target.resolveSibling(fileName + expectedExtension);
        }
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Export parent must be an existing directory");
        }
        if (Files.isSymbolicLink(target)) {
            throw new IOException("Refusing to overwrite a symbolic link");
        }
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) && !allowOverwrite) {
            throw new IOException("Export target already exists");
        }

        Path temporary = Files.createTempFile(parent, ".burp-framework-mapper-", ".tmp");
        try {
            Files.writeString(temporary, content, StandardCharsets.UTF_8);
            try {
                if (allowOverwrite) {
                    Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (AtomicMoveNotSupportedException exception) {
                if (allowOverwrite) {
                    Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.move(temporary, target);
                }
            }
            return target;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
