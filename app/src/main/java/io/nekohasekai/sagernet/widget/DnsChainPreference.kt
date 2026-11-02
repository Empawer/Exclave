package io.nekohasekai.sagernet.widget

import android.content.Context
import android.content.Intent
import android.util.AttributeSet
import androidx.preference.PreferenceViewHolder
import androidx.preference.SwitchPreference
import io.nekohasekai.sagernet.ui.DnsChainActivity

/**
 * A switch row where tapping the switch turns DNS Chain on/off,
 * and tapping anywhere else on the row opens the DNS Chain page.
 */
class DnsChainPreference : SwitchPreference {

    constructor(context: Context) : this(context, null)

    constructor(
        context: Context,
        attrs: AttributeSet?,
    ) : this(context, attrs, androidx.preference.R.attr.switchPreferenceStyle)

    constructor(
        context: Context,
        attrs: AttributeSet?,
        defStyleAttr: Int,
    ) : this(context, attrs, defStyleAttr, 0)

    constructor(
        context: Context,
        attrs: AttributeSet?,
        defStyleAttr: Int,
        defStyleRes: Int,
    ) : super(context, attrs, defStyleAttr, defStyleRes)

    override fun onBindViewHolder(holder: PreferenceViewHolder) {
        super.onBindViewHolder(holder)
        // by default the switch only mirrors the row; make it tappable on its own
        holder.findViewById(android.R.id.switch_widget)?.isClickable = true
    }

    // do not toggle when the row is tapped; open the settings page instead
    override fun onClick() {
        context.startActivity(Intent(context, DnsChainActivity::class.java))
    }
}
