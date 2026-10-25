package com.sentinelnet.app.ui.components

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.sentinelnet.app.R
import com.sentinelnet.core.consent.AuthorizationScope
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentDecision
import com.sentinelnet.core.consent.ConsentPolicy
import com.sentinelnet.core.domain.NetworkMath

/**
 * The ONE consent UI used for every invasive action. It renders the four
 * mandatory acknowledgements, scope selection, public-target justification and
 * biometric confirmation, then emits a single-use ConsentDecision bound to the
 * caller's nonce. Calling code cannot bypass ConsentGate: it must pass this
 * decision along with the same nonce.
 */
@Composable
fun ConsentDialog(
    capability: Capability,
    target: String,
    nonce: String,
    onDismiss: () -> Unit,
    onDecision: (ConsentDecision) -> Unit
) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    var a1 by remember { mutableStateOf(false) }
    var a2 by remember { mutableStateOf(false) }
    var a3 by remember { mutableStateOf(false) }
    var a4 by remember { mutableStateOf(false) }
    var scope by remember { mutableStateOf(AuthorizationScope.OWN_NETWORK) }
    var publicAck by remember { mutableStateOf(false) }
    var justification by remember { mutableStateOf("") }
    var biometricVerified by remember { mutableStateOf(false) }
    var biometricError by remember { mutableStateOf<String?>(null) }

    val isPublic = !NetworkMath.isPrivateOrLab(target.trim().substringBefore('/'))
    val allAcknowledged = a1 && a2 && a3 && a4
    val biometricOk = !capability.requiresBiometric || biometricVerified
    val canConfirm = allAcknowledged && biometricOk &&
        (!isPublic || (publicAck && justification.length >= 8))

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.consent_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("${capability.id}  •  ${stringResource(R.string.consent_target)}: $target",
                    style = MaterialTheme.typography.bodyMedium)
                ConsentCheckbox(R.string.consent_authorised_only, a1) { a1 = it }
                ConsentCheckbox(R.string.consent_understand_law, a2) { a2 = it }
                ConsentCheckbox(R.string.consent_audit_log, a3) { a3 = it }
                ConsentCheckbox(R.string.consent_no_exploitation, a4) { a4 = it }

                Text(stringResource(R.string.consent_scope), style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 10.dp))
                AuthorizationScope.entries.forEach { option ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = scope == option, onClick = { scope = option })
                        Text(option.name.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() })
                    }
                }

                if (isPublic) {
                    Text(stringResource(R.string.consent_public_warning),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 6.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = publicAck, onCheckedChange = { publicAck = it })
                        Text("I have written authorisation for this public target")
                    }
                    OutlinedTextField(
                        value = justification, onValueChange = { justification = it },
                        label = { Text(" Justification / engagement reference ") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = false, minLines = 2
                    )
                }

                if (capability.requiresBiometric) {
                    Button(
                        onClick = {
                            authenticate(
                                context, activity,
                                onSuccess = { biometricVerified = true; biometricError = null },
                                onError = { biometricError = it }
                            )
                        },
                        modifier = Modifier.padding(top = 10.dp)
                    ) {
                        Text(if (biometricVerified) "✓ ${stringResource(R.string.consent_biometric)}"
                        else stringResource(R.string.consent_biometric))
                    }
                    biometricError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                }
            }
        },
        confirmButton = {
            Button(
                enabled = canConfirm,
                onClick = {
                    onDecision(
                        ConsentDecision(
                            capability = capability,
                            nonce = nonce,
                            scope = scope,
                            target = target,
                            acknowledgedAuthorizedUse = a1,
                            acknowledgedLegalNoticeVersion = ConsentPolicy.CURRENT_NOTICE_VERSION,
                            biometricVerified = biometricVerified,
                            publicTargetAcknowledged = publicAck,
                            justification = justification,
                            grantedAtMillis = System.currentTimeMillis()
                        )
                    )
                },
                modifier = Modifier.semantics { contentDescription = "Confirm authorised action" }
            ) { Text(stringResource(R.string.consent_confirm)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.consent_cancel)) } }
    )
}

@Composable
private fun ConsentCheckbox(labelRes: Int, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(stringResource(labelRes), style = MaterialTheme.typography.bodyMedium)
    }
}

private fun authenticate(
    context: Context,
    activity: FragmentActivity?,
    onSuccess: () -> Unit,
    onError: (String) -> Unit
) {
    if (activity == null) { onError("Biometric prompt needs an activity"); return }
    val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(context),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onError(errString.toString())
            override fun onAuthenticationFailed() = onError("Biometric not recognised; try again")
        })
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm sensitive action")
        .setSubtitle("SentinelNet requires biometric confirmation for ${activity.getString(R.string.app_name)} security actions")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        .build()
    try { prompt.authenticate(info) } catch (t: Throwable) { onError(t.message ?: "Biometric unavailable") }
}
