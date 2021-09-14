package biz.netcentric.security.checkerdsl.payload

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class FilterEvasionTest {

    @BeforeEach
    void before() {

    }

    @Test
    void "extensions are correctly prefixed"() {
        List prefixes = ["children.-1.", "/].....harray.-1...."]

        List<String> expectedBypasses = FilterEvasion.DISPATCHER_BYPASS_EXTENSIONS.getBypasses()

        List<String> prefixedBypasses = FilterEvasion.DISPATCHER_BYPASS_EXTENSIONS.prefixBypasses(prefixes)

        def expectedLength = expectedBypasses.size() * prefixes.size()
        assertEquals(expectedLength, prefixedBypasses.size())

        expectedBypasses.each { bypass ->
            assertTrue(prefixedBypasses.contains(prefixes.get(0) + bypass))
            assertTrue(prefixedBypasses.contains(prefixes.get(1) + bypass))
        }
    }
}