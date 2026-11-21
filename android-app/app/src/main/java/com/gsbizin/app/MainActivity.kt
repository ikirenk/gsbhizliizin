package com.gsbizin.app

import android.graphics.BitmapFactory
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CalendarMonth
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DateRangePicker
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDateRangePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.gsbizin.app.network.EvciAddress
import com.gsbizin.app.network.GsbAuthAndApi
import com.gsbizin.app.network.LeaveResult
import com.gsbizin.app.network.LoginStepResult
import com.gsbizin.app.network.PendingCaptchaState
import com.gsbizin.app.network.PendingOtpState
import com.gsbizin.app.network.StudentSession
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                GsbIzinApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GsbIzinApp() {
    val api = remember { GsbAuthAndApi() }
    val scope = rememberCoroutineScope()

    var tc by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }

    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    var pendingOtp by remember { mutableStateOf<PendingOtpState?>(null) }
    var smsCode by remember { mutableStateOf("") }

    var pendingCaptcha by remember { mutableStateOf<PendingCaptchaState?>(null) }
    var captchaCode by remember { mutableStateOf("") }

    var studentSession by remember { mutableStateOf<StudentSession?>(null) }

    var startDate by remember { mutableStateOf(LocalDate.now()) }
    var endDate by remember { mutableStateOf(LocalDate.now().plusDays(1)) }
    var showDatePicker by remember { mutableStateOf(false) }

    var selectedEvci by remember { mutableStateOf<EvciAddress?>(null) }
    var evciExpanded by remember { mutableStateOf(false) }
    var phone by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("İzinli") }
    var leaveResult by remember { mutableStateOf<LeaveResult?>(null) }

    val displayFormatter = remember { DateTimeFormatter.ofPattern("dd.MM.yyyy") }
    val isoFormatter = remember { DateTimeFormatter.ofPattern("yyyy-MM-dd'T'00:00:00.000'Z'") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("GSB Yurt İzin") },
                actions = {
                    if (studentSession != null) {
                        TextButton(onClick = {
                            studentSession = null
                            leaveResult = null
                            errorMessage = null
                        }) {
                            Text("Çıkış")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (errorMessage != null) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = errorMessage!!,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }

            if (studentSession == null) {
                Text(
                    "e-Devlet Bilgileri ile Giriş",
                    style = MaterialTheme.typography.titleMedium
                )
                OutlinedTextField(
                    value = tc,
                    onValueChange = { if (it.length <= 11 && it.all(Char::isDigit)) tc = it },
                    label = { Text("T.C. Kimlik Numarası") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("e-Devlet Şifresi") },
                    visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { showPassword = !showPassword }) {
                            Icon(
                                imageVector = if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = null
                            )
                        }
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Button(
                    onClick = {
                        errorMessage = null
                        isLoading = true
                        scope.launch {
                            try {
                                when (val res = api.startLogin(tc.trim(), password)) {
                                    is LoginStepResult.NeedSmsOtp -> {
                                        smsCode = ""
                                        pendingOtp = res.state
                                    }
                                    is LoginStepResult.NeedCaptcha -> {
                                        captchaCode = ""
                                        pendingCaptcha = res.state
                                    }
                                    is LoginStepResult.Success -> {
                                        studentSession = res.session
                                        selectedEvci = res.session.evciAddresses.firstOrNull()
                                        if (phone.isEmpty()) phone = res.session.defaultPhone
                                    }
                                }
                            } catch (e: Exception) {
                                errorMessage = e.message ?: "Giriş sırasında hata oluştu."
                            } finally {
                                isLoading = false
                            }
                        }
                    },
                    enabled = !isLoading && tc.length == 11 && password.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                    } else {
                        Text("e-Devlet ile Giriş Yap")
                    }
                }
            } else {
                val session = studentSession!!

                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(session.fullName, style = MaterialTheme.typography.titleMedium)
                        if (session.leaveSummary.isNotEmpty()) {
                            Text(session.leaveSummary, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                OutlinedButton(
                    onClick = { showDatePicker = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.CalendarMonth, contentDescription = null)
                    Spacer(Modifier.padding(horizontal = 4.dp))
                    Text("Tarih Seç: ${startDate.format(displayFormatter)} - ${endDate.format(displayFormatter)}")
                }

                ExposedDropdownMenuBox(
                    expanded = evciExpanded,
                    onExpandedChange = { evciExpanded = !evciExpanded }
                ) {
                    OutlinedTextField(
                        value = selectedEvci?.adres ?: "Kayıtlı evci adresi bulunamadı",
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Evci Adresi") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = evciExpanded) },
                        modifier = Modifier
                            .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                            .fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = evciExpanded,
                        onDismissRequest = { evciExpanded = false }
                    ) {
                        session.evciAddresses.forEach { addr ->
                            DropdownMenuItem(
                                text = { Text(addr.adres) },
                                onClick = {
                                    selectedEvci = addr
                                    evciExpanded = false
                                }
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = phone,
                    onValueChange = { if (it.length <= 11 && it.all(Char::isDigit)) phone = it },
                    label = { Text("İrtibat Telefonu (05XXXXXXXXX)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Açıklama") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Button(
                    onClick = {
                        val evci = selectedEvci ?: return@Button
                        errorMessage = null
                        leaveResult = null
                        isLoading = true
                        scope.launch {
                            try {
                                leaveResult = api.submitLeaveRequest(
                                    jwtToken = session.jwtToken,
                                    baslangicIso = startDate.format(isoFormatter),
                                    bitisIso = endDate.format(isoFormatter),
                                    telefon = phone.trim(),
                                    evciId = evci.id,
                                    aciklama = description.trim().ifEmpty { "İzinli" }
                                )
                            } catch (e: Exception) {
                                errorMessage = e.message ?: "İzin talebi gönderilemedi."
                            } finally {
                                isLoading = false
                            }
                        }
                    },
                    enabled = !isLoading && selectedEvci != null && phone.length >= 10,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                    } else {
                        Text("İzin Talebi Gönder")
                    }
                }

                if (leaveResult != null) {
                    val res = leaveResult!!
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (res.success)
                                MaterialTheme.colorScheme.primaryContainer
                            else
                                MaterialTheme.colorScheme.errorContainer
                        ),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = res.message,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }
            }
        }
    }

    if (pendingOtp != null) {
        AlertDialog(
            onDismissRequest = { if (!isLoading) pendingOtp = null },
            title = { Text("SMS Doğrulama") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("e-Devlet tarafından gönderilen SMS doğrulama kodunu girin:")
                    OutlinedTextField(
                        value = smsCode,
                        onValueChange = { smsCode = it },
                        label = { Text("SMS Kodu") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val state = pendingOtp ?: return@Button
                        errorMessage = null
                        isLoading = true
                        scope.launch {
                            try {
                                when (val res = api.submitSmsOtp(state, smsCode)) {
                                    is LoginStepResult.NeedSmsOtp -> {
                                        smsCode = ""
                                        pendingOtp = res.state
                                    }
                                    is LoginStepResult.NeedCaptcha -> {
                                        pendingOtp = null
                                        captchaCode = ""
                                        pendingCaptcha = res.state
                                    }
                                    is LoginStepResult.Success -> {
                                        pendingOtp = null
                                        studentSession = res.session
                                        selectedEvci = res.session.evciAddresses.firstOrNull()
                                        if (phone.isEmpty()) phone = res.session.defaultPhone
                                    }
                                }
                            } catch (e: Exception) {
                                pendingOtp = null
                                errorMessage = e.message ?: "SMS doğrulaması başarısız."
                            } finally {
                                isLoading = false
                            }
                        }
                    },
                    enabled = !isLoading && smsCode.isNotBlank()
                ) {
                    Text("Doğrula")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingOtp = null }, enabled = !isLoading) {
                    Text("İptal")
                }
            }
        )
    }

    if (pendingCaptcha != null) {
        val cState = pendingCaptcha!!
        val captchaBitmap = remember(cState.imageBytes) {
            BitmapFactory.decodeByteArray(cState.imageBytes, 0, cState.imageBytes.size)?.asImageBitmap()
        }
        AlertDialog(
            onDismissRequest = { if (!isLoading) pendingCaptcha = null },
            title = { Text("Güvenlik Kodu (CAPTCHA)") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("e-Devlet güvenlik görselindeki kodu girin:")
                    if (captchaBitmap != null) {
                        Image(
                            bitmap = captchaBitmap,
                            contentDescription = "CAPTCHA",
                            contentScale = ContentScale.Fit,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(80.dp)
                        )
                    } else {
                        Text("Görsel yüklenemedi.", color = MaterialTheme.colorScheme.error)
                    }
                    OutlinedTextField(
                        value = captchaCode,
                        onValueChange = { captchaCode = it },
                        label = { Text("Güvenlik Kodu") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        errorMessage = null
                        isLoading = true
                        scope.launch {
                            try {
                                when (val res = api.submitCaptcha(cState, captchaCode, tc.trim(), password)) {
                                    is LoginStepResult.NeedSmsOtp -> {
                                        pendingCaptcha = null
                                        smsCode = ""
                                        pendingOtp = res.state
                                    }
                                    is LoginStepResult.NeedCaptcha -> {
                                        captchaCode = ""
                                        pendingCaptcha = res.state
                                    }
                                    is LoginStepResult.Success -> {
                                        pendingCaptcha = null
                                        studentSession = res.session
                                        selectedEvci = res.session.evciAddresses.firstOrNull()
                                        if (phone.isEmpty()) phone = res.session.defaultPhone
                                    }
                                }
                            } catch (e: Exception) {
                                pendingCaptcha = null
                                errorMessage = e.message ?: "CAPTCHA doğrulaması başarısız."
                            } finally {
                                isLoading = false
                            }
                        }
                    },
                    enabled = !isLoading && captchaCode.isNotBlank()
                ) {
                    Text("Gönder")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingCaptcha = null }, enabled = !isLoading) {
                    Text("İptal")
                }
            }
        )
    }

    if (showDatePicker) {
        val pickerState = rememberDateRangePickerState(
            initialSelectedStartDateMillis = startDate.atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli(),
            initialSelectedEndDateMillis = endDate.atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli()
        )
        DatePickerDialog(
            onDismissRequest = { showDatePicker = false },
            confirmButton = {
                TextButton(
                    onClick = {
                        val sMillis = pickerState.selectedStartDateMillis
                        val eMillis = pickerState.selectedEndDateMillis ?: sMillis
                        if (sMillis != null && eMillis != null) {
                            startDate = Instant.ofEpochMilli(sMillis).atZone(ZoneOffset.UTC).toLocalDate()
                            endDate = Instant.ofEpochMilli(eMillis).atZone(ZoneOffset.UTC).toLocalDate()
                        }
                        showDatePicker = false
                    }
                ) {
                    Text("Seç")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDatePicker = false }) {
                    Text("İptal")
                }
            }
        ) {
            DateRangePicker(
                state = pickerState,
                modifier = Modifier.weight(1f)
            )
        }
    }
}
