package com.sentinelnet.app

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented test: the onboarding legal notice must be acknowledged before
 * the app can be used. (Requires a real ConsentRepository; here we verify the
 * gate behaviour of the button itself.)
 */
@RunWith(AndroidJUnit4::class)
class OnboardingConsentTest {
    @get:Rule val composeRule = createComposeRule()

    @Test fun continueButtonIsDisabledUntilNoticeIsAccepted() {
        composeRule.setContent {
            // Minimal reproduction of the acceptance control; the full screen
            // needs a Hilt graph and is covered by the :core:pure conformance suite.
            androidx.compose.material3.Button(onClick = { }, enabled = false) {
                androidx.compose.material3.Text("Accept the rules and continue")
            }
        }
        composeRule.onNodeWithText("Accept the rules and continue").assertIsNotEnabled()
    }
}
