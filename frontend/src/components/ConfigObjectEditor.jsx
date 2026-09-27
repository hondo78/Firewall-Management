import { ObjectEditor, RuleEditor } from './Editors'
import { RestObjectEditor } from './RestEditors'
import { SophosNatEditor, SophosRuleEditor } from './SophosRules'
import { WafRuleEditor } from './SophosWaf'

/**
 * Passendes Formular für ein Konfigurationsobjekt (als Dialog): Firewall-/NAT-/WAF-Regeln im SFOS-Aufbau,
 * übrige Objekte mit ihren Formularen; XML-Format mit den XML-Editoren. onSubmit(op) erhält die Operation.
 */
export default function ConfigObjectEditor({ format, entity, label, config, obj, onClose, onSubmit }) {
  const props = { config, onClose, onSubmit }
  if (format === 'xml') {
    return entity === 'FirewallRule' ? <RuleEditor {...props} rule={obj} /> : <ObjectEditor {...props} entity={entity} label={label} object={obj} />
  }
  if (entity.startsWith('firewallRules')) return <SophosRuleEditor {...props} entity={entity} rule={obj} />
  if (entity === 'natRulesIpv4') return <SophosNatEditor {...props} entity={entity} rule={obj} />
  if (entity === 'wafRules') return <WafRuleEditor {...props} rule={obj} />
  return <RestObjectEditor {...props} entity={entity} label={label} object={obj} />
}
