/*
 *
 *  * (C) Copyright 2016 Netcentric AG.
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */
package biz.netcentric.security.checkerdsl.dsl.securitycheck

import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.Test
import org.junit.jupiter.api.BeforeEach
import org.mockito.Mockito

class HttpSecurityCheckDefinitionTest {

    @BeforeEach
    void prepare() {

    }

    @Test
    void configureSingleStepTest() {
        HttpSecurityCheck check = HttpSecurityCheck.create("Check 1",
                {},
                {
                    id "check-id-1"

                    name "Single step test"
                })

        HttpSecurityCheckStep step = check.getSteps().get(0)
        Assert.assertEquals "check-id-1", step.getId()
        Assert.assertEquals "Single step test", step.getName()
    }

    @Test
    void configureMultiStepTest() {
        def check1 = {
            id "check-id-1"

            name "step 1 test"
        }

        def check2 = {
            id "check-id-2"

            name "step 2 test"

        }

        HttpSecurityCheck check = HttpSecurityCheck.create("Check 2", {}, [check1, check2])

        HttpSecurityCheckStep step = check.getSteps().get(0)
        Assert.assertEquals "check-id-1", step.getId()
        Assert.assertEquals "step 1 test", step.getName()

        step = check.getSteps().get(1)
        Assert.assertEquals "check-id-2", step.getId()
        Assert.assertEquals "step 2 test", step.getName()
    }

    @Test
    void callDependantMultiStepRunnerDelegatesTest() {
        List<HttpSecurityCheckStep> steps = []

        // overrides runner delegate as it is not intended do any subsequent call in here right now.
        // just interested in the process of delegation
        // the step runner must return an Issue else it will stop immedtialy
        int called = 0
        HttpSecurityCheckRunner.metaClass.execute = { HttpSecurityCheckStep checkStep ->
            called++
            [new Issue()]
        }

        [1, 2].each { i ->
            String identifier = "check-" + i

            HttpSecurityCheckStep check = HttpSecurityCheckStep.create({
                id identifier + "-id"
                name identifier + "-name"
            })

            steps << check
        }

        AsyncHttpClient preConfiguredHttpClient = Mockito.mock(AsyncHttpClient.class)
        ScanContext context = Mockito.mock(ScanContext)
        HttpSecurityCheck check = HttpSecurityCheck.createSecurityCheckWithSteps("Check 2", {}, steps)

        check(preConfiguredHttpClient, context)

        Assert.assertEquals 2, called
    }

    @Test
    void "stop after second step does not return any results"() {
        List<HttpSecurityCheckStep> steps = []

        // overrides runner delegate as it is not intended do any subsequent call in here right now.
        // just interested in the process of delegation
        // the step runner must return an Issue else it will stop immedtialy
        int called = 0
        HttpSecurityCheckRunner.metaClass.execute = { HttpSecurityCheckStep checkStep ->
            called++

            return called < 2 ? [new Issue()] : []
        }

        [1, 2, 3].each { i ->
            String identifier = "check-" + i

            HttpSecurityCheckStep check = HttpSecurityCheckStep.create({
                id identifier + "-id"
                name identifier + "-name"
            })

            steps << check
        }

        AsyncHttpClient preConfiguredHttpClient = Mockito.mock(AsyncHttpClient.class)
        ScanContext context = Mockito.mock(ScanContext)
        HttpSecurityCheck check = HttpSecurityCheck.createSecurityCheckWithSteps("Some Security Check with 3 steps", {}, steps)

        check(preConfiguredHttpClient, context)

        Assert.assertEquals 2, called
    }
}
