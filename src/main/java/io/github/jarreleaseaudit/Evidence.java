package io.github.jarreleaseaudit;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

record Evidence(String id, Finding finding) {
    static List<Evidence> from(Report report) {
        List<Evidence> result = new ArrayList<>();
        for (int i = 0; i < report.findings().size(); i++)
            result.add(new Evidence(String.format(Locale.ROOT, "F%05d", i + 1), report.findings().get(i)));
        return List.copyOf(result);
    }
}
