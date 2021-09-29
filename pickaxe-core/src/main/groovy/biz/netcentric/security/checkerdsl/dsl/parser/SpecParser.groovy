package biz.netcentric.security.checkerdsl.dsl.parser


import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.config.Spec

/**
 * Parses a Spec to create HttpSecurityChecks
 */
interface SpecParser {

    List<HttpSecurityCheck> createCheck(Spec script)
}