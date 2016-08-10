<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
	<fieldset>
		<legend><?php echo __('Import from MISP Export File'); ?></legend>
<?php
	echo $this->Form->input('Event.submittedfile', array(
			'label' => '<b>MISP XML or JSON file</b>',
			'type' => 'file',
	));
	if (Configure::read('MISP.take_ownership_xml_import')):
?>
		<div class="input clear"></div>
<?php
	echo $this->Form->input('Event.takeownership', array(
			'checked' => false,
			'label' => 'Take ownership of the event',
			'title' => 'Warning: This will change the creator organisation of the event, tampering with the event\'s ownership and releasability and can lead to unexpected behaviour when synchronising the event with instances that have another creator for the same event.'
	));
	endif;
?>
	</fieldset>
<?php
	echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>

<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
  <fieldset>
    <legend><?php echo __('Import from STIX format'); ?></legend>
<?php
  echo $this->Form->input('Event.submittedfile_stix', array(
      'label' => '<b>STIX XML or JSON file</b>',
      'type' => 'file',
  ));
  if (Configure::read('MISP.take_ownership_xml_import')):
?>
    <div class="input clear"></div>
<?php
  echo $this->Form->input('Event.takeownership', array(
      'checked' => false,
      'label' => 'Take ownership of the event',
      'title' => 'Warning: This will change the creator organisation of the event, tampering with the event\'s ownership and releasability and can lead to unexpected behaviour when synchronising the event with instances that have another creator for the same event.'
  ));
  endif;
?>
  </fieldset>
<?php
  echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
  echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addMISPExport'));
?>
