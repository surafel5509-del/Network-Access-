package com.sentinelnet.app.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.sentinelnet.app.R
import com.sentinelnet.app.ui.screens.AuditScreen
import com.sentinelnet.app.ui.screens.DashboardScreen
import com.sentinelnet.app.ui.screens.OnboardingScreen
import com.sentinelnet.app.ui.screens.ReportsScreen
import com.sentinelnet.app.ui.screens.ScannerScreen
import com.sentinelnet.app.ui.screens.SecurityLabScreen
import com.sentinelnet.app.ui.screens.SettingsScreen
import com.sentinelnet.app.ui.screens.WifiScreen
import com.sentinelnet.core.android.di.ConsentRepository
import com.sentinelnet.core.android.ui.SentinelGreen

private data class Destination(val route: String, val labelRes: Int, val icon: ImageVector)

private val destinations = listOf(
    Destination("dashboard", R.string.nav_dashboard, Icons.Filled.Home),
    Destination("wifi", R.string.nav_wifi, Icons.Filled.Wifi),
    Destination("scanner", R.string.nav_scanner, Icons.Filled.Radar),
    Destination("audit", R.string.nav_audit, Icons.Filled.Security),
    Destination("lab", R.string.nav_lab, Icons.Filled.Science),
    Destination("settings", R.string.nav_settings, Icons.Filled.Settings)
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SentinelNavHost(repository: ConsentRepository) {
    val onboardingDone by repository.onboardingDone().collectAsStateWithLifecycle(initialValue = false)
    if (!onboardingDone) {
        OnboardingScreen(onFinished = { /* DataStore emission triggers recomposition */ })
        return
    }

    val navController = rememberNavController()
    val backStack by navController.currentBackStackEntryAsState()
    val current = backStack?.destination

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleMedium)
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = SentinelGreen
                )
            )
        },
        bottomBar = {
            NavigationBar {
                destinations.forEach { d ->
                    NavigationBarItem(
                        selected = current?.hierarchy?.any { it.route == d.route } == true,
                        onClick = {
                            navController.navigate(d.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(d.icon, contentDescription = stringResource(d.labelRes)) },
                        label = { Text(stringResource(d.labelRes), style = MaterialTheme.typography.labelSmall) }
                    )
                }
            }
        }
    ) { padding ->
        NavHost(navController, startDestination = "dashboard", Modifier.padding(padding)) {
            composable("dashboard") { DashboardScreen(onNavigate = { navController.navigate(it) }) }
            composable("wifi") { WifiScreen() }
            composable("scanner") { ScannerScreen() }
            composable("audit") { AuditScreen() }
            composable("lab") { SecurityLabScreen() }
            composable("reports") { ReportsScreen() }
            composable("settings") { SettingsScreen() }
        }
    }
}
