package io.ntnl.exe

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { textSize = 16f; setPadding(24, 48, 24, 24) }
        val start = Button(this).apply { text = "Serve calls" }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                addView(status)
                addView(start)
            },
        )
        val dir = filesDir.absolutePath
        status.text = "This device: ${Client.address(dir) ?: "no key"}\n\n" +
            "Add this address in the console, then give this device the console's address " +
            "with `exe trust <address>`. No pairing code exists."
        start.setOnClickListener {
            Client.start(dir, "https://exe.ntnl.io")
            status.text = "Serving calls as ${Client.address(dir)}"
        }
    }
}
