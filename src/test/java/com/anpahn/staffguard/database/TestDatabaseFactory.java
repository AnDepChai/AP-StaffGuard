package com.anpahn.staffguard.database;

import java.io.File;
import java.io.InputStream;
import java.util.Objects;
import java.util.function.Function;

/** Test-only bridge for constructing an isolated Database without widening the production API. */
public final class TestDatabaseFactory {
    private TestDatabaseFactory() {
    }

    public static Database create(File file, Function<String, InputStream> resourceLoader) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(resourceLoader, "resourceLoader");
        return new Database(null, file, resourceLoader);
    }
}
