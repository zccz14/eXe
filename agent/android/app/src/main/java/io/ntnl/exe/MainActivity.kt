package io.ntnl.exe

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.File

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { textSize = 16f; setPadding(24, 48, 24, 24) }
        val start = Button(this).apply { text = "Connect this device" }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                addView(status)
                addView(start)
            },
        )
        start.setOnClickListener {
            val dir = filesDir.absolutePath
            status.text = "Starting… approve the code that appears here."
            Agent.start(dir, "https://exe.ntnl.io")
            poll(dir)
        }
    }

    private fun poll(dir: String) {
        handler.postDelayed({
            val file = File(dir, "pairing.txt")
            status.text =
                if (file.exists()) {
                    val (code, uri) = file.readLines().plus("").take(2).let { it[0] to it.getOrElse(1) { "" } }
                    "Pairing code: $code\nApprove at: $uri\n\nCompare the SAS shown in the console with the one on this screen."
                } else {
                    "Running. Nothing to approve."
                }
            poll(dir)
        }, 1000)
    }
}
