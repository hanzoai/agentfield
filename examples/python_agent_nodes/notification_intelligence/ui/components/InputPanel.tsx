'use client'

import React from 'react'

function cn(...classes: (string | undefined | false)[]) {
  return classes.filter(Boolean).join(' ')
}

interface Scenario {
  id: string
  name: string
  description: string
}

type ScenarioMode = 'predefined' | 'custom'

const NOTIFICATION_TYPES = [
  { value: 'abandoned_cart', label: 'Abandoned Cart', icon: '🛒' },
  { value: 'flash_sale', label: 'Flash Sale', icon: '⚡' },
  { value: 'back_in_stock', label: 'Back in Stock', icon: '📦' },
  { value: 'price_drop', label: 'Price Drop', icon: '💰' },
  { value: 'shipping_update', label: 'Shipping Update', icon: '🚚' },
]

export interface CustomFormData {
  notification_type: string
  cart_value?: number
  items?: string
  abandoned_minutes?: number
  discount_percent?: number
  expires_hours?: number
  category?: string
  item_name?: string
  item_price?: number
  stock_quantity?: number
  original_price?: number
  new_price?: number
  order_id?: string
  delivery_status?: string
  estimated_delivery?: string
  user_tier?: string
  previous_purchases?: number
  notifications_today?: number
  user_currently_browsing?: boolean
  hour_in_user_timezone?: number
  recent_notifications_ignored?: number
  user_engagement_level?: string
}

interface InputPanelProps {
  scenarios: Scenario[]
  selectedScenarioId: string
  setSelectedScenarioId: (id: string) => void
  scenarioMode: ScenarioMode
  setScenarioMode: (mode: ScenarioMode) => void
  customForm: CustomFormData
  setCustomForm: React.Dispatch<React.SetStateAction<CustomFormData>>
  isRunning: boolean
  onRunPredefined: () => void
  onRunCustom: () => void
  className?: string
}

export function InputPanel({
  scenarios,
  selectedScenarioId,
  setSelectedScenarioId,
  scenarioMode,
  setScenarioMode,
  customForm,
  setCustomForm,
  isRunning,
  onRunPredefined,
  onRunCustom,
  className,
}: InputPanelProps) {
  const selectedScenario = scenarios.find((s) => s.id === selectedScenarioId)

  return (
    <div className={cn('flex flex-col h-full bg-zinc-900/30 border-r border-zinc-800', className)}>
      {/* Header */}
      <div className="p-4 border-b border-zinc-800 bg-zinc-900/50 shrink-0">
        <h2 className="font-semibold text-sm text-zinc-400 uppercase tracking-wider">
          Configuration
        </h2>
      </div>

      {/* Scrollable Content */}
      <div className="flex-1 overflow-y-auto">
        {/* Tabs */}
        <div className="flex border-b border-zinc-800 sticky top-0 bg-zinc-900/80 backdrop-blur-sm z-10">
          <button
            onClick={() => setScenarioMode('predefined')}
            disabled={isRunning}
            className={cn(
              'flex-1 px-4 py-2.5 text-xs font-medium transition-all',
              scenarioMode === 'predefined'
                ? 'bg-zinc-800 text-indigo-400 border-b-2 border-indigo-500'
                : 'text-zinc-500 hover:text-zinc-300'
            )}
          >
            Predefined Scenarios
          </button>
          <button
            onClick={() => setScenarioMode('custom')}
            disabled={isRunning}
            className={cn(
              'flex-1 px-4 py-2.5 text-xs font-medium transition-all',
              scenarioMode === 'custom'
                ? 'bg-zinc-800 text-indigo-400 border-b-2 border-indigo-500'
                : 'text-zinc-500 hover:text-zinc-300'
            )}
          >
            Custom Scenario
          </button>
        </div>

        <div className="p-4">
          {scenarioMode === 'predefined' ? (
            <div className="space-y-3">
              <div>
                <label className="block text-[10px] text-zinc-500 uppercase tracking-wider mb-1.5">
                  Select Scenario
                </label>
                <select
                  value={selectedScenarioId}
                  onChange={(e) => setSelectedScenarioId(e.target.value)}
                  disabled={isRunning}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20"
                >
                  {scenarios.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>
              {selectedScenario && (
                <p className="text-xs text-zinc-500 leading-relaxed">{selectedScenario.description}</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {/* Notification Type */}
              <div>
                <label className="block text-[10px] text-zinc-500 uppercase tracking-wider mb-2">
                  Notification Type
                </label>
                <div className="grid grid-cols-3 gap-1.5">
                  {NOTIFICATION_TYPES.map((type) => (
                    <button
                      key={type.value}
                      onClick={() => setCustomForm((f) => ({ ...f, notification_type: type.value }))}
                      disabled={isRunning}
                      className={cn(
                        'px-2 py-1.5 rounded-lg text-center transition-all',
                        customForm.notification_type === type.value
                          ? 'bg-indigo-600 text-white ring-1 ring-indigo-500'
                          : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
                      )}
                    >
                      <div className="text-sm">{type.icon}</div>
                      <div className="text-[9px] font-medium leading-tight">{type.label}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Dynamic Fields Based on Type */}
              <div className="space-y-3">
                {customForm.notification_type === 'abandoned_cart' && (
                  <>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">
                        Cart Value ($)
                      </label>
                      <input
                        type="number"
                        value={customForm.cart_value || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, cart_value: parseFloat(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">
                        Items (comma-separated)
                      </label>
                      <input
                        type="text"
                        value={customForm.items || ''}
                        onChange={(e) => setCustomForm((f) => ({ ...f, items: e.target.value }))}
                        disabled={isRunning}
                        placeholder="Shoes, Watch, Bag"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">
                        Minutes Abandoned
                      </label>
                      <input
                        type="number"
                        value={customForm.abandoned_minutes || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, abandoned_minutes: parseInt(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </>
                )}

                {customForm.notification_type === 'flash_sale' && (
                  <>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Discount %</label>
                      <input
                        type="number"
                        value={customForm.discount_percent || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, discount_percent: parseInt(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">
                        Expires In (hours)
                      </label>
                      <input
                        type="number"
                        value={customForm.expires_hours || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, expires_hours: parseInt(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Category</label>
                      <input
                        type="text"
                        value={customForm.category || ''}
                        onChange={(e) => setCustomForm((f) => ({ ...f, category: e.target.value }))}
                        disabled={isRunning}
                        placeholder="Electronics"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </>
                )}

                {customForm.notification_type === 'back_in_stock' && (
                  <>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Item Name</label>
                      <input
                        type="text"
                        value={customForm.item_name || ''}
                        onChange={(e) => setCustomForm((f) => ({ ...f, item_name: e.target.value }))}
                        disabled={isRunning}
                        placeholder="Sony Headphones"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Price ($)</label>
                      <input
                        type="number"
                        value={customForm.item_price || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, item_price: parseFloat(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Stock Qty</label>
                      <input
                        type="number"
                        value={customForm.stock_quantity || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, stock_quantity: parseInt(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </>
                )}

                {customForm.notification_type === 'price_drop' && (
                  <>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Item Name</label>
                      <input
                        type="text"
                        value={customForm.item_name || ''}
                        onChange={(e) => setCustomForm((f) => ({ ...f, item_name: e.target.value }))}
                        disabled={isRunning}
                        placeholder="Dyson Vacuum"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">
                        Original Price ($)
                      </label>
                      <input
                        type="number"
                        value={customForm.original_price || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, original_price: parseFloat(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">New Price ($)</label>
                      <input
                        type="number"
                        value={customForm.new_price || ''}
                        onChange={(e) =>
                          setCustomForm((f) => ({ ...f, new_price: parseFloat(e.target.value) || 0 }))
                        }
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </>
                )}

                {customForm.notification_type === 'shipping_update' && (
                  <>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Order ID</label>
                      <input
                        type="text"
                        value={customForm.order_id || ''}
                        onChange={(e) => setCustomForm((f) => ({ ...f, order_id: e.target.value }))}
                        disabled={isRunning}
                        placeholder="ORD-12345"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">Status</label>
                      <select
                        value={customForm.delivery_status || 'out_for_delivery'}
                        onChange={(e) => setCustomForm((f) => ({ ...f, delivery_status: e.target.value }))}
                        disabled={isRunning}
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      >
                        <option value="shipped">Shipped</option>
                        <option value="out_for_delivery">Out for Delivery</option>
                        <option value="delivered">Delivered</option>
                        <option value="delayed">Delayed</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] text-zinc-500 uppercase mb-1.5">
                        Est. Delivery
                      </label>
                      <input
                        type="text"
                        value={customForm.estimated_delivery || ''}
                        onChange={(e) => setCustomForm((f) => ({ ...f, estimated_delivery: e.target.value }))}
                        disabled={isRunning}
                        placeholder="Today by 6 PM"
                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </>
                )}
              </div>

              {/* User Context */}
              <div className="pt-3 border-t border-zinc-800">
                <div className="text-[10px] text-zinc-400 uppercase tracking-wider mb-2">User Context</div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Tier</label>
                    <select
                      value={customForm.user_tier || 'standard'}
                      onChange={(e) => setCustomForm((f) => ({ ...f, user_tier: e.target.value }))}
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="standard">Standard</option>
                      <option value="silver">Silver</option>
                      <option value="gold">Gold</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Purchases</label>
                    <input
                      type="number"
                      value={customForm.previous_purchases || 0}
                      onChange={(e) =>
                        setCustomForm((f) => ({ ...f, previous_purchases: parseInt(e.target.value) || 0 }))
                      }
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Engagement</label>
                    <select
                      value={customForm.user_engagement_level || 'high'}
                      onChange={(e) => setCustomForm((f) => ({ ...f, user_engagement_level: e.target.value }))}
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Browsing Now</label>
                    <select
                      value={customForm.user_currently_browsing ? 'yes' : 'no'}
                      onChange={(e) =>
                        setCustomForm((f) => ({ ...f, user_currently_browsing: e.target.value === 'yes' }))
                      }
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="no">No</option>
                      <option value="yes">Yes (on site)</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Fatigue Signals */}
              <div className="pt-3 border-t border-zinc-800">
                <div className="text-[10px] text-red-400/80 uppercase tracking-wider mb-2">
                  Fatigue Signals (may cause skip/delay)
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Notifs Today</label>
                    <input
                      type="number"
                      min="0"
                      max="20"
                      value={customForm.notifications_today || 0}
                      onChange={(e) =>
                        setCustomForm((f) => ({ ...f, notifications_today: parseInt(e.target.value) || 0 }))
                      }
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Recent Ignored</label>
                    <input
                      type="number"
                      min="0"
                      max="10"
                      value={customForm.recent_notifications_ignored || 0}
                      onChange={(e) =>
                        setCustomForm((f) => ({
                          ...f,
                          recent_notifications_ignored: parseInt(e.target.value) || 0,
                        }))
                      }
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-zinc-500 mb-1">Hour (0-23)</label>
                    <input
                      type="number"
                      min="0"
                      max="23"
                      value={customForm.hour_in_user_timezone ?? 14}
                      onChange={(e) =>
                        setCustomForm((f) => ({ ...f, hour_in_user_timezone: parseInt(e.target.value) || 0 }))
                      }
                      disabled={isRunning}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Footer with Button */}
      <div className="p-4 border-t border-zinc-800 bg-zinc-900/50 shrink-0">
        <button
          onClick={scenarioMode === 'predefined' ? onRunPredefined : onRunCustom}
          disabled={isRunning || (scenarioMode === 'predefined' && !selectedScenarioId)}
          className="w-full px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-zinc-800 disabled:text-zinc-600 rounded-lg text-sm font-medium transition-all shadow-lg hover:shadow-xl"
        >
          {isRunning ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>
    </div>
  )
}
